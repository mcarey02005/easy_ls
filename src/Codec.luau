--!nonstrict
--[[
	Purpose:
		Encode an Instance tree into a JSON-safe DOM table, then decode that DOM
		back into an Instance tree.

	Important truth:
		Roblox does not allow every property to be read/written from every context.
		This module attempts every reflected property it can see through ReflectionService,
		but any security-protected, read-only, computed, non-creatable, unsupported, or
		otherwise failing property is recorded in the returned report instead of being
		silently ignored.

	Script source:
		For Script / LocalScript / ModuleScript, this module prefers ScriptEditorService
		when available. That keeps long source strings intact and sees edit-time source
		when running as a Studio plugin. Source strings are base64-encoded in the JSON DOM
		by default so 10k+ character scripts do not get damaged by JSON escaping / UTF-8
		edge cases.

	DOM shape:
		{
			format = "RobloxInstanceJSONDOM",
			version = 1,
			root = {
				id = "1",
				class = "Folder",
				properties = {
					Name = { type = "string", value = "MyFolder" },
				},
				attributes = {},
				tags = {},
				children = {},
				skipped = {},
			},
		}

	Public API:
		local Codec = require(path.To.InstanceDomCodec)

		local dom, encodeReport = Codec.Encode(instance, options?)
		local json, encodeReport = Codec.EncodeToJSON(instance, options?)

		local clone, decodeReport = Codec.Decode(dom, options?)
		local clone, decodeReport = Codec.DecodeFromJSON(json, options?)

	Decode scheduling:
		Decode / DecodeFromJSON yield cooperatively during instance construction and
		property application by default after about 0.2 seconds of work. Pass
		{ DecodeYieldAfterSeconds = false } to disable, or set a number to tune it.

	Recommended plugin usage:
		local Selection = game:GetService("Selection")
		local selected = Selection:Get()[1]
		local json, report = Codec.EncodeToJSON(selected)
		print(json)
]]

local HttpService = game:GetService("HttpService")

local Codec = {}
Codec.Format = "RobloxInstanceJSONDOM"
Codec.Version = 3

-- Services are resolved lazily so this module can still load in older/stubbed contexts.
local ReflectionService = nil
local ScriptEditorService = nil
local CollectionService = nil

local function getReflectionService()
	if ReflectionService ~= nil then
		return ReflectionService
	end

	local ok, service = pcall(function()
		return game:GetService("ReflectionService")
	end)

	if ok then
		ReflectionService = service
	else
		ReflectionService = false
	end

	return ReflectionService ~= false and ReflectionService or nil
end

local function getScriptEditorService()
	if ScriptEditorService ~= nil then
		return ScriptEditorService
	end

	local ok, service = pcall(function()
		return game:GetService("ScriptEditorService")
	end)

	if ok then
		ScriptEditorService = service
	else
		ScriptEditorService = false
	end

	return ScriptEditorService ~= false and ScriptEditorService or nil
end

local function getCollectionService()
	if CollectionService ~= nil then
		return CollectionService
	end

	local ok, service = pcall(function()
		return game:GetService("CollectionService")
	end)

	if ok then
		CollectionService = service
	else
		CollectionService = false
	end

	return CollectionService ~= false and CollectionService or nil
end

local function makeReport(mode)
	return {
		mode = mode,
		instances = 0,
		propertiesRead = 0,
		propertiesWritten = 0,
		propertiesReapplied = 0,
		attributesRead = 0,
		attributesWritten = 0,
		tagsRead = 0,
		tagsWritten = 0,
		schedulerYields = 0,
		skipped = {},
		failedReads = {},
		failedWrites = {},
		unsupportedValues = {},
		externalReferences = {},
		warnings = {},
	}
end

local function push(list, item)
	list[#list + 1] = item
end

local DEFAULT_DECODE_YIELD_AFTER_SECONDS = 0.2
local DEFAULT_DECODE_YIELD_CHECK_INTERVAL = 64

local function makeDecodeYieldState(options, report)
	if options.DecodeYieldAfterSeconds == false then
		return nil
	end

	if task == nil or type(task.wait) ~= "function" then
		push(report.warnings, "Decode yielding is unavailable because task.wait is unavailable.")
		return nil
	end

	return {
		wait = task.wait,
		yieldAfterSeconds = options.DecodeYieldAfterSeconds,
		checkInterval = options.DecodeYieldCheckInterval,
		checkCount = 0,
		lastYieldTime = os.clock(),
	}
end

local function maybeYield(ctx, forceCheck)
	local state = ctx and ctx.decodeYieldState
	if state == nil then
		return
	end

	if not forceCheck then
		state.checkCount += 1
		if state.checkCount < state.checkInterval then
			return
		end
		state.checkCount = 0
	end

	local now = os.clock()
	if now - state.lastYieldTime < state.yieldAfterSeconds then
		return
	end

	state.wait()
	state.lastYieldTime = os.clock()
	ctx.report.schedulerYields += 1
end

local function safeToString(value)
	local ok, result = pcall(function()
		return tostring(value)
	end)

	if ok then
		return result
	end

	return "<tostring failed>"
end

local function errorToString(err)
	if err == nil then
		return "<nil error>"
	end

	return safeToString(err)
end

local function mergeOptions(options)
	options = options or {}

	local decodeYieldAfterSeconds = options.DecodeYieldAfterSeconds
	if decodeYieldAfterSeconds == nil then
		decodeYieldAfterSeconds = options.YieldAfterSeconds
	end
	if decodeYieldAfterSeconds == nil then
		decodeYieldAfterSeconds = DEFAULT_DECODE_YIELD_AFTER_SECONDS
	end
	if type(decodeYieldAfterSeconds) ~= "number" or decodeYieldAfterSeconds <= 0 then
		decodeYieldAfterSeconds = false
	end

	local decodeYieldCheckInterval = options.DecodeYieldCheckInterval or DEFAULT_DECODE_YIELD_CHECK_INTERVAL
	if type(decodeYieldCheckInterval) ~= "number" or decodeYieldCheckInterval < 1 then
		decodeYieldCheckInterval = DEFAULT_DECODE_YIELD_CHECK_INTERVAL
	end

	local merged = {
		-- Try to ask ReflectionService for the broadest reflected API surface.
		-- Actual read/write still happens through pcall and can still fail.
		UseAllSecurityCapabilities = options.UseAllSecurityCapabilities ~= false,

		-- Include properties where ReflectionService says Serialized == false.
		-- User asked for all properties, so default is true.
		IncludeNonSerializedProperties = options.IncludeNonSerializedProperties ~= false,

		-- Include attributes and tags in addition to properties.
		IncludeAttributes = options.IncludeAttributes ~= false,
		IncludeTags = options.IncludeTags ~= false,

		-- For script source, prefer ScriptEditorService over direct .Source.
		PreferScriptEditorSource = options.PreferScriptEditorSource ~= false,
		IncludeScriptSource = options.IncludeScriptSource ~= false,

		-- Base64 large strings and script source so JSON cannot corrupt bytes.
		EncodeScriptSourceAsBase64 = options.EncodeScriptSourceAsBase64 ~= false,
		EncodeAllStringsAsBase64 = options.EncodeAllStringsAsBase64 == true,
		EncodeLongStringsAsBase64Over = options.EncodeLongStringsAsBase64Over or 2048,

		-- If false, properties that error are reported but encode/decode continues.
		FailOnPropertyError = options.FailOnPropertyError == true,

		-- Decode behavior for classes that cannot be Instance.new'd.
		UseExistingServicesForNonCreatable = options.UseExistingServicesForNonCreatable == true,
		UseExistingTerrainForNonCreatable = options.UseExistingTerrainForNonCreatable == true,
		AllowFolderFallbackForNonCreatable = options.AllowFolderFallbackForNonCreatable == true,

		-- GuiObject.Transparency is a hidden mixed/alias property. On text UI it can
		-- overwrite TextTransparency after TextTransparency has already been written.
		-- Keep it encoded for completeness, but do not write it by default during
		-- Decode. Set this true only if you are intentionally decoding an old/custom
		-- DOM that contains Transparency but not concrete transparency properties.
		DecodeGuiObjectTransparencyAlias = options.DecodeGuiObjectTransparencyAlias == true,

		-- Same alias problem on encode: keep this false by default so a freshly
		-- encoded DOM cannot preserve the dangerous mixed alias and then corrupt
		-- TextTransparency during decode in older/custom decoders. Set true only
		-- if you explicitly need the hidden GuiObject.Transparency alias recorded.
		EncodeGuiObjectTransparencyAlias = options.EncodeGuiObjectTransparencyAlias == true,

		-- Where decoded root should be parented after the whole tree is built.
		Parent = options.Parent,

		-- Optional callback for external ObjectValue/Weld/etc refs outside encoded tree.
		-- function(encodedExternalRef) -> Instance?
		ResolveExternalInstanceRef = options.ResolveExternalInstanceRef,

		-- Optional sets:
		-- ExcludeProperties = { PropertyName = true }
		-- IncludeProperties = { PropertyName = true } -- nil means include all attempted props
		ExcludeProperties = options.ExcludeProperties or {},
		IncludeProperties = options.IncludeProperties,

		-- Optional class gates for decode.
		AllowedClasses = options.AllowedClasses,
		DeniedClasses = options.DeniedClasses or {},

		-- Cooperative decode scheduling. DecodeFromJSON cannot yield inside
		-- HttpService:JSONDecode, but the instance/property build can yield.
		DecodeYieldAfterSeconds = decodeYieldAfterSeconds,
		DecodeYieldCheckInterval = decodeYieldCheckInterval,
	}

	return merged
end

-- Parent/ClassName are represented structurally, not as settable properties.
local RESERVED_PROPERTIES = {
	Parent = true,
	ClassName = true,
	className = true,
}

-- Write order matters for alias/computed properties. This does not solve every class-specific
-- interaction, but it prevents common transform/source issues from being worse than necessary.
local PROPERTY_PRIORITY = {
	Name = 0,
	Archivable = 1,
	Disabled = 10,
	Enabled = 10,
	Source = 50,

	Size = 100,

	-- Hidden/deprecated GUI aggregate transparency must be applied before concrete
	-- transparency properties if the caller explicitly enables decoding it. In
	-- normal decode it is skipped entirely; this order is just a safety net.
	Transparency = 200,
	BackgroundTransparency = 650,
	ImageTransparency = 650,
	GroupTransparency = 650,
	TextTransparency = 650,
	TextStrokeTransparency = 650,

	Position = 800,
	Orientation = 801,
	Rotation = 802,
	CFrame = 900,
	PivotOffset = 901,
	WorldPivot = 902,
	PrimaryPart = 1000,
}

local function getPropertyPriority(name)
	return PROPERTY_PRIORITY[name] or 500
end

local GUI_CONCRETE_TRANSPARENCY_PROPERTIES = {
	"BackgroundTransparency",
	"ImageTransparency",
	"GroupTransparency",
	"TextTransparency",
	"TextStrokeTransparency",
}

local function sortNamesForDecode(properties)
	local names = {}

	for name in pairs(properties or {}) do
		names[#names + 1] = name
	end

	table.sort(names, function(a, b)
		local pa = getPropertyPriority(a)
		local pb = getPropertyPriority(b)
		if pa ~= pb then
			return pa < pb
		end
		return a < b
	end)

	return names
end

local function isA(instance, className)
	local ok, result = pcall(function()
		return instance:IsA(className)
	end)

	return ok and result == true
end

-- GuiObject.Transparency is reflected as a property, but Roblox documents it as
-- hidden/not replicated and as a mixed property of BackgroundTransparency and
-- TextTransparency. During a full-property decode, writing this alias after the
-- concrete properties can corrupt text UI by forcing TextTransparency to the
-- alias value. Therefore the DOM keeps it, but Decode skips it by default.
local function shouldSkipGuiObjectTransparencyAlias(instance, propertyName, node, ctx)
	if propertyName ~= "Transparency" then
		return false, nil
	end

	if ctx.options.DecodeGuiObjectTransparencyAlias then
		return false, nil
	end

	if not isA(instance, "GuiObject") then
		return false, nil
	end

	return true, "skipped hidden GuiObject.Transparency mixed alias; concrete transparency properties are decoded instead"
end

local didTryAllCapabilities = false
local cachedAllCapabilities = nil

local function getAllSecurityCapabilities()
	if didTryAllCapabilities then
		return cachedAllCapabilities
	end

	didTryAllCapabilities = true

	local ok, capabilities = pcall(function()
		return SecurityCapabilities.new(table.unpack(Enum.SecurityCapability:GetEnumItems()))
	end)

	if ok then
		cachedAllCapabilities = capabilities
	end

	return cachedAllCapabilities
end

local function describeReflectionType(reflectionType)
	local luaType = typeof(reflectionType)

	if luaType == "string" then
		return reflectionType
	end

	if luaType == "EnumItem" then
		return safeToString(reflectionType)
	end

	if luaType ~= "table" then
		return safeToString(reflectionType)
	end

	local direct = reflectionType.Name
		or reflectionType.Type
		or reflectionType.Category
		or reflectionType.ClassName
		or reflectionType.ValueType

	if direct ~= nil then
		return safeToString(direct)
	end

	return "<reflection type table>"
end

local reflectedPropertyCache = {}

local function getReflectedProperties(className, options, report)
	local cacheKey = className .. "|" .. tostring(options.IncludeNonSerializedProperties) .. "|" .. tostring(options.UseAllSecurityCapabilities)
	if reflectedPropertyCache[cacheKey] ~= nil then
		return reflectedPropertyCache[cacheKey]
	end

	local reflection = getReflectionService()
	if not reflection then
		push(report.warnings, "ReflectionService is unavailable; only manually added properties can be encoded.")
		reflectedPropertyCache[cacheKey] = {}
		return reflectedPropertyCache[cacheKey]
	end

	local filter = {
		ExcludeInherited = false,
		ExcludeDisplay = true,
	}

	if options.UseAllSecurityCapabilities then
		local capabilities = getAllSecurityCapabilities()
		if capabilities ~= nil then
			filter.Security = capabilities
		end
	end

	local ok, reflected = pcall(function()
		return reflection:GetPropertiesOfClass(className, filter)
	end)

	if not ok or type(reflected) ~= "table" then
		push(report.warnings, "ReflectionService:GetPropertiesOfClass failed for " .. className .. ": " .. errorToString(reflected))
		reflectedPropertyCache[cacheKey] = {}
		return reflectedPropertyCache[cacheKey]
	end

	local byName = {}
	for _, propertyInfo in ipairs(reflected) do
		if type(propertyInfo) == "table" and type(propertyInfo.Name) == "string" then
			if options.IncludeNonSerializedProperties or propertyInfo.Serialized == true then
				byName[propertyInfo.Name] = propertyInfo
			end
		end
	end

	local result = {}
	for _, propertyInfo in pairs(byName) do
		push(result, propertyInfo)
	end

	table.sort(result, function(a, b)
		return a.Name < b.Name
	end)

	reflectedPropertyCache[cacheKey] = result
	return result
end

local function isLuaSourceContainer(instance)
	local ok, result = pcall(function()
		return instance:IsA("LuaSourceContainer")
	end)

	return ok and result == true
end

local function getScriptSource(instance, ctx)
	if ctx.options.PreferScriptEditorSource then
		local scriptEditor = getScriptEditorService()
		if scriptEditor then
			local ok, source = pcall(function()
				return scriptEditor:GetEditorSource(instance)
			end)

			if ok and type(source) == "string" then
				return true, source, "ScriptEditorService:GetEditorSource"
			end
		end
	end

	local ok, source = pcall(function()
		return instance.Source
	end)

	if ok and type(source) == "string" then
		return true, source, "Instance.Source"
	end

	return false, errorToString(source), nil
end

local function setScriptSource(instance, source, ctx)
	if ctx.options.PreferScriptEditorSource then
		local scriptEditor = getScriptEditorService()
		if scriptEditor then
			local ok, err = pcall(function()
				scriptEditor:UpdateSourceAsync(instance, function(_oldSource)
					return source
				end)
			end)

			if ok then
				return true, "ScriptEditorService:UpdateSourceAsync"
			end
		end
	end

	local ok, err = pcall(function()
		instance.Source = source
	end)

	if ok then
		return true, "Instance.Source"
	end

	return false, errorToString(err)
end

-- Minimal base64 implementation. Used for script source, long strings, buffers,
-- and binary-ish string properties.
local BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local BASE64_LOOKUP = {}
for i = 1, #BASE64_ALPHABET do
	BASE64_LOOKUP[string.sub(BASE64_ALPHABET, i, i)] = i - 1
end

local function base64Encode(data)
	local out = {}
	local outIndex = 0
	local length = #data

	for i = 1, length, 3 do
		local b1 = string.byte(data, i) or 0
		local b2 = string.byte(data, i + 1) or 0
		local b3 = string.byte(data, i + 2) or 0
		local remaining = length - i + 1

		local triple = b1 * 65536 + b2 * 256 + b3
		local c1 = math.floor(triple / 262144) % 64
		local c2 = math.floor(triple / 4096) % 64
		local c3 = math.floor(triple / 64) % 64
		local c4 = triple % 64

		outIndex += 1
		out[outIndex] = string.sub(BASE64_ALPHABET, c1 + 1, c1 + 1)
		outIndex += 1
		out[outIndex] = string.sub(BASE64_ALPHABET, c2 + 1, c2 + 1)
		outIndex += 1
		out[outIndex] = remaining >= 2 and string.sub(BASE64_ALPHABET, c3 + 1, c3 + 1) or "="
		outIndex += 1
		out[outIndex] = remaining >= 3 and string.sub(BASE64_ALPHABET, c4 + 1, c4 + 1) or "="
	end

	return table.concat(out)
end

local function base64Decode(data, ctx)
	local clean = string.gsub(data, "%s", "")
	if #clean % 4 ~= 0 then
		error("invalid base64 length")
	end

	local out = {}
	local outIndex = 0

	for i = 1, #clean, 4 do
		if i % 8192 == 1 then
			maybeYield(ctx, true)
		end

		local ch1 = string.sub(clean, i, i)
		local ch2 = string.sub(clean, i + 1, i + 1)
		local ch3 = string.sub(clean, i + 2, i + 2)
		local ch4 = string.sub(clean, i + 3, i + 3)

		local c1 = BASE64_LOOKUP[ch1]
		local c2 = BASE64_LOOKUP[ch2]
		local c3 = ch3 == "=" and 0 or BASE64_LOOKUP[ch3]
		local c4 = ch4 == "=" and 0 or BASE64_LOOKUP[ch4]

		if c1 == nil or c2 == nil or c3 == nil or c4 == nil then
			error("invalid base64 character")
		end

		local triple = c1 * 262144 + c2 * 4096 + c3 * 64 + c4
		local b1 = math.floor(triple / 65536) % 256
		local b2 = math.floor(triple / 256) % 256
		local b3 = triple % 256

		outIndex += 1
		out[outIndex] = string.char(b1)
		if ch3 ~= "=" then
			outIndex += 1
			out[outIndex] = string.char(b2)
		end
		if ch4 ~= "=" then
			outIndex += 1
			out[outIndex] = string.char(b3)
		end
	end

	return table.concat(out)
end

local function isValidUtf8(str)
	if utf8 == nil or utf8.len == nil then
		return true
	end

	local ok, lenOrErr = pcall(function()
		return utf8.len(str)
	end)

	return ok and lenOrErr ~= nil
end

local function stringShouldUseBase64(str, hint, options)
	if options.EncodeAllStringsAsBase64 then
		return true
	end

	if hint and hint.propertyName == "Source" and options.EncodeScriptSourceAsBase64 then
		return true
	end

	if options.EncodeLongStringsAsBase64Over and #str >= options.EncodeLongStringsAsBase64Over then
		return true
	end

	if string.find(str, "%z") ~= nil then
		return true
	end

	if not isValidUtf8(str) then
		return true
	end

	local reflectedType = hint and hint.reflectedType or ""
	if reflectedType == "BinaryString" or reflectedType == "SharedString" then
		return true
	end

	return false
end

local function encodeEnumItem(enumItem)
	local enumTypeText = safeToString(enumItem.EnumType)
	local enumName = string.gsub(enumTypeText, "^Enum%.", "")

	return {
		type = "EnumItem",
		enum = enumName,
		name = enumItem.Name,
		value = enumItem.Value,
	}
end

local function decodeEnumItem(encoded)
	local enumName = encoded.enum or encoded.enumType
	local enumObject = Enum[enumName]
	if enumObject == nil then
		error("unknown enum: " .. safeToString(enumName))
	end

	if encoded.name ~= nil then
		local byName = enumObject[encoded.name]
		if byName ~= nil then
			return byName
		end
	end

	if encoded.value ~= nil then
		for _, item in ipairs(enumObject:GetEnumItems()) do
			if item.Value == encoded.value then
				return item
			end
		end
	end

	error("unknown enum item: " .. safeToString(enumName) .. "." .. safeToString(encoded.name))
end

local function packVector2(v)
	return { x = v.X, y = v.Y }
end

local function unpackVector2(v)
	return Vector2.new(v.x or v[1] or 0, v.y or v[2] or 0)
end

local function packVector3(v)
	return { x = v.X, y = v.Y, z = v.Z }
end

local function unpackVector3(v)
	return Vector3.new(v.x or v[1] or 0, v.y or v[2] or 0, v.z or v[3] or 0)
end

local function packColor3(c)
	return { r = c.R, g = c.G, b = c.B }
end

local function unpackColor3(c)
	return Color3.new(c.r or c[1] or 0, c.g or c[2] or 0, c.b or c[3] or 0)
end

local function packUDim(u)
	return { scale = u.Scale, offset = u.Offset }
end

local function unpackUDim(u)
	return UDim.new(u.scale or u[1] or 0, u.offset or u[2] or 0)
end

local function packCFrame(cf)
	return { cf:GetComponents() }
end

local function unpackCFrame(components)
	return CFrame.new(table.unpack(components))
end

local function bufferToString(buf)
	if buffer == nil then
		error("buffer library is unavailable")
	end

	local len = buffer.len(buf)
	local out = {}
	for i = 0, len - 1 do
		out[#out + 1] = string.char(buffer.readu8(buf, i))
	end
	return table.concat(out)
end

local function stringToBuffer(str, ctx)
	if buffer == nil then
		error("buffer library is unavailable")
	end

	local buf = buffer.create(#str)
	for i = 1, #str do
		if i % 8192 == 1 then
			maybeYield(ctx, true)
		end

		buffer.writeu8(buf, i - 1, string.byte(str, i))
	end
	return buf
end

local encodeValue = nil
local decodeValue = nil
local valueContainsInstanceReference = nil

local function encodeTable(value, ctx, hint, seenTables)
	seenTables = seenTables or {}
	if seenTables[value] then
		return {
			type = "Unsupported",
			valueType = "table",
			reason = "cyclic table",
		}
	end

	seenTables[value] = true

	local entries = {}
	for k, v in pairs(value) do
		local encodedKey = encodeValue(k, ctx, nil, seenTables)
		local encodedValue = encodeValue(v, ctx, nil, seenTables)
		push(entries, {
			key = encodedKey,
			value = encodedValue,
		})
	end

	seenTables[value] = nil

	return {
		type = "table",
		entries = entries,
	}
end

encodeValue = function(value, ctx, hint, seenTables)
	local valueType = typeof(value)

	if value == nil then
		return { type = "nil" }
	end

	if valueType == "boolean" then
		return { type = "boolean", value = value }
	end

	if valueType == "number" then
		if value ~= value then
			return { type = "number", special = "nan" }
		elseif value == math.huge then
			return { type = "number", special = "inf" }
		elseif value == -math.huge then
			return { type = "number", special = "-inf" }
		end

		return { type = "number", value = value }
	end

	if valueType == "string" then
		if stringShouldUseBase64(value, hint, ctx.options) then
			return {
				type = "string",
				encoding = "base64",
				value = base64Encode(value),
				length = #value,
			}
		end

		return { type = "string", value = value }
	end

	if valueType == "Vector2" then
		return { type = "Vector2", value = packVector2(value) }
	end

	if valueType == "Vector2int16" then
		return { type = "Vector2int16", value = { x = value.X, y = value.Y } }
	end

	if valueType == "Vector3" then
		return { type = "Vector3", value = packVector3(value) }
	end

	if valueType == "Vector3int16" then
		return { type = "Vector3int16", value = { x = value.X, y = value.Y, z = value.Z } }
	end

	if valueType == "Color3" then
		return { type = "Color3", value = packColor3(value) }
	end

	if valueType == "UDim" then
		return { type = "UDim", value = packUDim(value) }
	end

	if valueType == "UDim2" then
		return {
			type = "UDim2",
			value = {
				x = packUDim(value.X),
				y = packUDim(value.Y),
			},
		}
	end

	if valueType == "CFrame" then
		return { type = "CFrame", value = packCFrame(value) }
	end

	if valueType == "EnumItem" then
		return encodeEnumItem(value)
	end

	if valueType == "BrickColor" then
		return {
			type = "BrickColor",
			name = safeToString(value),
			number = value.Number,
		}
	end

	if valueType == "NumberRange" then
		return {
			type = "NumberRange",
			min = value.Min,
			max = value.Max,
		}
	end

	if valueType == "NumberSequenceKeypoint" then
		return {
			type = "NumberSequenceKeypoint",
			time = value.Time,
			value = value.Value,
			envelope = value.Envelope,
		}
	end

	if valueType == "NumberSequence" then
		local keypoints = {}
		for _, kp in ipairs(value.Keypoints) do
			push(keypoints, encodeValue(kp, ctx))
		end
		return { type = "NumberSequence", keypoints = keypoints }
	end

	if valueType == "ColorSequenceKeypoint" then
		return {
			type = "ColorSequenceKeypoint",
			time = value.Time,
			color = packColor3(value.Value),
		}
	end

	if valueType == "ColorSequence" then
		local keypoints = {}
		for _, kp in ipairs(value.Keypoints) do
			push(keypoints, encodeValue(kp, ctx))
		end
		return { type = "ColorSequence", keypoints = keypoints }
	end

	if valueType == "Rect" then
		return {
			type = "Rect",
			min = packVector2(value.Min),
			max = packVector2(value.Max),
		}
	end

	if valueType == "Ray" then
		return {
			type = "Ray",
			origin = packVector3(value.Origin),
			direction = packVector3(value.Direction),
		}
	end

	if valueType == "Region3" then
		local cf = value.CFrame
		local size = value.Size
		local half = size / 2
		return {
			type = "Region3",
			min = packVector3(cf.Position - half),
			max = packVector3(cf.Position + half),
		}
	end

	if valueType == "Region3int16" then
		return {
			type = "Region3int16",
			min = { x = value.Min.X, y = value.Min.Y, z = value.Min.Z },
			max = { x = value.Max.X, y = value.Max.Y, z = value.Max.Z },
		}
	end

	if valueType == "Faces" then
		return {
			type = "Faces",
			Top = value.Top,
			Bottom = value.Bottom,
			Left = value.Left,
			Right = value.Right,
			Front = value.Front,
			Back = value.Back,
		}
	end

	if valueType == "Axes" then
		return {
			type = "Axes",
			X = value.X,
			Y = value.Y,
			Z = value.Z,
		}
	end

	if valueType == "PhysicalProperties" then
		return {
			type = "PhysicalProperties",
			density = value.Density,
			friction = value.Friction,
			elasticity = value.Elasticity,
			frictionWeight = value.FrictionWeight,
			elasticityWeight = value.ElasticityWeight,
		}
	end

	if valueType == "Font" then
		return {
			type = "Font",
			family = value.Family,
			weight = encodeValue(value.Weight, ctx),
			style = encodeValue(value.Style, ctx),
		}
	end

	if valueType == "Content" then
		local sourceType = value.SourceType
		local sourceTypeName = sourceType and sourceType.Name or nil

		if sourceTypeName == "Uri" then
			return {
				type = "Content",
				sourceType = "Uri",
				uri = value.Uri,
			}
		elseif sourceTypeName == "Object" then
			return {
				type = "Content",
				sourceType = "Object",
				object = encodeValue(value.Object, ctx),
			}
		elseif sourceTypeName == "None" then
			return {
				type = "Content",
				sourceType = "None",
			}
		else
			return {
				type = "Unsupported",
				valueType = "Content",
				reason = "Content source type is not supported: " .. safeToString(sourceTypeName),
			}
		end
	end

	if valueType == "DateTime" then
		return {
			type = "DateTime",
			unixTimestampMillis = value.UnixTimestampMillis,
		}
	end

	if valueType == "TweenInfo" then
		return {
			type = "TweenInfo",
			time = value.Time,
			easingStyle = encodeValue(value.EasingStyle, ctx),
			easingDirection = encodeValue(value.EasingDirection, ctx),
			repeatCount = value.RepeatCount,
			reverses = value.Reverses,
			delayTime = value.DelayTime,
		}
	end

	if valueType == "PathWaypoint" then
		return {
			type = "PathWaypoint",
			position = packVector3(value.Position),
			action = encodeValue(value.Action, ctx),
			label = value.Label,
		}
	end

	if valueType == "Instance" then
		local id = ctx.instanceToId and ctx.instanceToId[value]
		if id ~= nil then
			return {
				type = "InstanceRef",
				ref = id,
			}
		end

		local external = {
			type = "ExternalInstanceRef",
			class = value.ClassName,
			name = value.Name,
			path = value:GetFullName(),
		}
		push(ctx.report.externalReferences, external)
		return external
	end

	if valueType == "buffer" then
		local raw = bufferToString(value)
		return {
			type = "buffer",
			encoding = "base64",
			value = base64Encode(raw),
			length = #raw,
		}
	end

	if valueType == "table" then
		return encodeTable(value, ctx, hint, seenTables)
	end

	if valueType == "Secret" then
		return {
			type = "Unsupported",
			valueType = "Secret",
			reason = "Secret values are intentionally not serialized",
		}
	end

	return {
		type = "Unsupported",
		valueType = valueType,
		string = safeToString(value),
		reason = "No serializer registered for typeof(value)",
	}
end

valueContainsInstanceReference = function(encoded, ctx)
	if type(encoded) ~= "table" then
		return false
	end

	if encoded.type == "InstanceRef" or encoded.type == "ExternalInstanceRef" then
		return true
	end

	if encoded.type == "Content" and encoded.object ~= nil then
		return valueContainsInstanceReference(encoded.object, ctx)
	end

	if encoded.type == "table" then
		for _, entry in ipairs(encoded.entries or {}) do
			maybeYield(ctx)
			if valueContainsInstanceReference(entry.key, ctx) or valueContainsInstanceReference(entry.value, ctx) then
				return true
			end
		end
	end

	return false
end

decodeValue = function(encoded, ctx)
	if encoded == nil then
		return nil
	end

	local encodedType = encoded.type

	if encodedType == "nil" then
		return nil
	end

	if encodedType == "boolean" then
		return encoded.value == true
	end

	if encodedType == "number" then
		if encoded.special == "nan" then
			return 0 / 0
		elseif encoded.special == "inf" then
			return math.huge
		elseif encoded.special == "-inf" then
			return -math.huge
		end
		return encoded.value
	end

	if encodedType == "string" then
		if encoded.encoding == "base64" then
			return base64Decode(encoded.value or "", ctx)
		end
		return encoded.value or ""
	end

	if encodedType == "Vector2" then
		return unpackVector2(encoded.value or {})
	end

	if encodedType == "Vector2int16" then
		local v = encoded.value or {}
		return Vector2int16.new(v.x or v[1] or 0, v.y or v[2] or 0)
	end

	if encodedType == "Vector3" then
		return unpackVector3(encoded.value or {})
	end

	if encodedType == "Vector3int16" then
		local v = encoded.value or {}
		return Vector3int16.new(v.x or v[1] or 0, v.y or v[2] or 0, v.z or v[3] or 0)
	end

	if encodedType == "Color3" then
		return unpackColor3(encoded.value or {})
	end

	if encodedType == "UDim" then
		return unpackUDim(encoded.value or {})
	end

	if encodedType == "UDim2" then
		local v = encoded.value or {}
		local x = unpackUDim(v.x or {})
		local y = unpackUDim(v.y or {})
		return UDim2.new(x.Scale, x.Offset, y.Scale, y.Offset)
	end

	if encodedType == "CFrame" then
		return unpackCFrame(encoded.value or { 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1 })
	end

	if encodedType == "EnumItem" then
		return decodeEnumItem(encoded)
	end

	if encodedType == "BrickColor" then
		if encoded.number ~= nil then
			return BrickColor.new(encoded.number)
		end
		return BrickColor.new(encoded.name or "Medium stone grey")
	end

	if encodedType == "NumberRange" then
		return NumberRange.new(encoded.min or 0, encoded.max or encoded.min or 0)
	end

	if encodedType == "NumberSequenceKeypoint" then
		return NumberSequenceKeypoint.new(encoded.time or 0, encoded.value or 0, encoded.envelope or 0)
	end

	if encodedType == "NumberSequence" then
		local keypoints = {}
		for _, encodedKp in ipairs(encoded.keypoints or {}) do
			maybeYield(ctx)
			push(keypoints, decodeValue(encodedKp, ctx))
		end
		return NumberSequence.new(keypoints)
	end

	if encodedType == "ColorSequenceKeypoint" then
		return ColorSequenceKeypoint.new(encoded.time or 0, unpackColor3(encoded.color or {}))
	end

	if encodedType == "ColorSequence" then
		local keypoints = {}
		for _, encodedKp in ipairs(encoded.keypoints or {}) do
			maybeYield(ctx)
			push(keypoints, decodeValue(encodedKp, ctx))
		end
		return ColorSequence.new(keypoints)
	end

	if encodedType == "Rect" then
		return Rect.new(unpackVector2(encoded.min or {}), unpackVector2(encoded.max or {}))
	end

	if encodedType == "Ray" then
		return Ray.new(unpackVector3(encoded.origin or {}), unpackVector3(encoded.direction or {}))
	end

	if encodedType == "Region3" then
		return Region3.new(unpackVector3(encoded.min or {}), unpackVector3(encoded.max or {}))
	end

	if encodedType == "Region3int16" then
		local min = encoded.min or {}
		local max = encoded.max or {}
		return Region3int16.new(
			Vector3int16.new(min.x or min[1] or 0, min.y or min[2] or 0, min.z or min[3] or 0),
			Vector3int16.new(max.x or max[1] or 0, max.y or max[2] or 0, max.z or max[3] or 0)
		)
	end

	if encodedType == "Faces" then
		local faces = {}
		if encoded.Top then push(faces, Enum.NormalId.Top) end
		if encoded.Bottom then push(faces, Enum.NormalId.Bottom) end
		if encoded.Left then push(faces, Enum.NormalId.Left) end
		if encoded.Right then push(faces, Enum.NormalId.Right) end
		if encoded.Front then push(faces, Enum.NormalId.Front) end
		if encoded.Back then push(faces, Enum.NormalId.Back) end
		return Faces.new(table.unpack(faces))
	end

	if encodedType == "Axes" then
		local axes = {}
		if encoded.X then push(axes, Enum.Axis.X) end
		if encoded.Y then push(axes, Enum.Axis.Y) end
		if encoded.Z then push(axes, Enum.Axis.Z) end
		return Axes.new(table.unpack(axes))
	end

	if encodedType == "PhysicalProperties" then
		return PhysicalProperties.new(
			encoded.density or 0,
			encoded.friction or 0,
			encoded.elasticity or 0,
			encoded.frictionWeight or 0,
			encoded.elasticityWeight or 0
		)
	end

	if encodedType == "Font" then
		local weight = decodeValue(encoded.weight, ctx) or Enum.FontWeight.Regular
		local style = decodeValue(encoded.style, ctx) or Enum.FontStyle.Normal
		return Font.new(encoded.family or "rbxasset://fonts/families/SourceSansPro.json", weight, style)
	end

	if encodedType == "Content" then
		if encoded.sourceType == "Uri" then
			return Content.fromUri(encoded.uri or "")
		elseif encoded.sourceType == "Object" then
			local object = decodeValue(encoded.object, ctx)
			if object == nil then
				error("Content.fromObject could not resolve object reference")
			end
			return Content.fromObject(object)
		elseif encoded.sourceType == "None" then
			local ok, none = pcall(function()
				return Content.none
			end)
			if ok and none ~= nil then
				return none
			end
			return Content.fromUri("")
		end
		error("unsupported Content sourceType: " .. safeToString(encoded.sourceType))
	end

	if encodedType == "DateTime" then
		return DateTime.fromUnixTimestampMillis(encoded.unixTimestampMillis or 0)
	end

	if encodedType == "TweenInfo" then
		return TweenInfo.new(
			encoded.time or 0,
			decodeValue(encoded.easingStyle, ctx) or Enum.EasingStyle.Quad,
			decodeValue(encoded.easingDirection, ctx) or Enum.EasingDirection.Out,
			encoded.repeatCount or 0,
			encoded.reverses == true,
			encoded.delayTime or 0
		)
	end

	if encodedType == "PathWaypoint" then
		return PathWaypoint.new(
			unpackVector3(encoded.position or {}),
			decodeValue(encoded.action, ctx),
			encoded.label or ""
		)
	end

	if encodedType == "InstanceRef" then
		return ctx.idToInstance and ctx.idToInstance[encoded.ref] or nil
	end

	if encodedType == "ExternalInstanceRef" then
		if type(ctx.options.ResolveExternalInstanceRef) == "function" then
			return ctx.options.ResolveExternalInstanceRef(encoded)
		end
		return nil
	end

	if encodedType == "buffer" then
		return stringToBuffer(base64Decode(encoded.value or "", ctx), ctx)
	end

	if encodedType == "table" then
		local result = {}
		for _, entry in ipairs(encoded.entries or {}) do
			maybeYield(ctx)
			local key = decodeValue(entry.key, ctx)
			local value = decodeValue(entry.value, ctx)
			if key ~= nil then
				result[key] = value
			end
		end
		return result
	end

	if encodedType == "Unsupported" then
		error("unsupported encoded value: " .. safeToString(encoded.valueType) .. " / " .. safeToString(encoded.reason))
	end

	error("unknown encoded value type: " .. safeToString(encodedType))
end

local function shouldAttemptProperty(propertyName, propertyInfo, instance, options)
	if RESERVED_PROPERTIES[propertyName] then
		return false, "reserved structural property"
	end

	if options.ExcludeProperties[propertyName] then
		return false, "excluded by options.ExcludeProperties"
	end

	if options.IncludeProperties ~= nil and not options.IncludeProperties[propertyName] then
		return false, "not present in options.IncludeProperties"
	end

	if propertyName == "Source" and not options.IncludeScriptSource then
		return false, "script source disabled by options.IncludeScriptSource"
	end

	if propertyName == "Transparency" and isA(instance, "GuiObject") and not options.EncodeGuiObjectTransparencyAlias then
		return false, "skipped hidden GuiObject.Transparency mixed alias; concrete transparency properties are encoded instead"
	end

	return true, nil
end

local function addManualPropertiesIfNeeded(instance, properties)
	local seen = {}
	for _, prop in ipairs(properties) do
		seen[prop.Name] = true
	end

	-- Source can be security-filtered or absent depending on context. Since the user
	-- specifically requested full scripts, force an attempt for LuaSourceContainer.
	if isLuaSourceContainer(instance) and not seen.Source then
		push(properties, {
			Name = "Source",
			Serialized = true,
			Type = "ProtectedString",
			Manual = true,
		})
	end

	table.sort(properties, function(a, b)
		return a.Name < b.Name
	end)
end

local function readProperty(instance, propertyName, propertyInfo, ctx)
	if propertyName == "Source" and isLuaSourceContainer(instance) then
		local ok, sourceOrErr, method = getScriptSource(instance, ctx)
		if ok then
			return true, sourceOrErr, method
		end
		return false, sourceOrErr, method
	end

	local ok, value = pcall(function()
		return instance[propertyName]
	end)

	if ok then
		return true, value, nil
	end

	return false, errorToString(value), nil
end

local function writeProperty(instance, propertyName, encodedValue, ctx)
	local decodedValue = nil
	local okDecode, decodeErr = pcall(function()
		decodedValue = decodeValue(encodedValue, ctx)
	end)

	if not okDecode then
		return false, "decode failed: " .. errorToString(decodeErr)
	end

	if propertyName == "Source" and isLuaSourceContainer(instance) then
		local ok, methodOrErr = setScriptSource(instance, decodedValue, ctx)
		if ok then
			return true, methodOrErr
		end
		return false, methodOrErr
	end

	-- Hard guard: this is intentionally duplicated from applyPropertiesPass.
	-- It protects callers that invoke writeProperty through future code paths and
	-- prevents GuiObject.Transparency from ever touching TextTransparency unless
	-- explicitly enabled.
	if propertyName == "Transparency" and isA(instance, "GuiObject") and not ctx.options.DecodeGuiObjectTransparencyAlias then
		return true, "skipped hidden GuiObject.Transparency mixed alias"
	end

	local okWrite, writeErr = pcall(function()
		instance[propertyName] = decodedValue
	end)

	if okWrite then
		return true, nil
	end

	return false, errorToString(writeErr)
end

local function getTagsSafe(instance)
	local ok, tags = pcall(function()
		return instance:GetTags()
	end)

	if ok and type(tags) == "table" then
		return tags
	end

	local collection = getCollectionService()
	if collection then
		local ok2, tags2 = pcall(function()
			return collection:GetTags(instance)
		end)
		if ok2 and type(tags2) == "table" then
			return tags2
		end
	end

	return {}
end

local function addTagSafe(instance, tag)
	local ok = pcall(function()
		instance:AddTag(tag)
	end)

	if ok then
		return true
	end

	local collection = getCollectionService()
	if collection then
		local ok2 = pcall(function()
			collection:AddTag(instance, tag)
		end)
		return ok2
	end

	return false
end

local function assignIds(root, ctx)
	ctx.nextId += 1
	ctx.instanceToId[root] = tostring(ctx.nextId)

	for _, child in ipairs(root:GetChildren()) do
		assignIds(child, ctx)
	end
end

local function encodeInstance(instance, ctx)
	ctx.report.instances += 1

	local id = ctx.instanceToId[instance]
	local node = {
		id = id,
		class = instance.ClassName,
		properties = {},
		attributes = {},
		tags = {},
		children = {},
		skipped = {},
	}

	local properties = getReflectedProperties(instance.ClassName, ctx.options, ctx.report)
	local propertyCopy = {}
	for _, prop in ipairs(properties) do
		propertyCopy[#propertyCopy + 1] = prop
	end
	addManualPropertiesIfNeeded(instance, propertyCopy)

	for _, propertyInfo in ipairs(propertyCopy) do
		local propertyName = propertyInfo.Name
		local shouldAttempt, skipReason = shouldAttemptProperty(propertyName, propertyInfo, instance, ctx.options)

		if not shouldAttempt then
			local item = {
				id = id,
				class = instance.ClassName,
				property = propertyName,
				reason = skipReason,
			}
			push(node.skipped, item)
			push(ctx.report.skipped, item)
		else
			local okRead, valueOrErr, readMethod = readProperty(instance, propertyName, propertyInfo, ctx)
			if not okRead then
				local item = {
					id = id,
					class = instance.ClassName,
					property = propertyName,
					reason = valueOrErr,
				}
				push(node.skipped, item)
				push(ctx.report.failedReads, item)

				if ctx.options.FailOnPropertyError then
					error("Failed to read " .. instance:GetFullName() .. "." .. propertyName .. ": " .. valueOrErr)
				end
			else
				local reflectedType = describeReflectionType(propertyInfo.Type)
				local hint = {
					propertyName = propertyName,
					reflectedType = reflectedType,
				}

				local okEncode, encodedOrErr = pcall(function()
					return encodeValue(valueOrErr, ctx, hint)
				end)

				if not okEncode then
					local item = {
						id = id,
						class = instance.ClassName,
						property = propertyName,
						reason = "encode failed: " .. errorToString(encodedOrErr),
					}
					push(node.skipped, item)
					push(ctx.report.unsupportedValues, item)
				elseif type(encodedOrErr) == "table" and encodedOrErr.type == "Unsupported" then
					encodedOrErr.reflectedType = reflectedType
					encodedOrErr.serialized = propertyInfo.Serialized == true
					node.properties[propertyName] = encodedOrErr
					push(ctx.report.unsupportedValues, {
						id = id,
						class = instance.ClassName,
						property = propertyName,
						valueType = encodedOrErr.valueType,
						reason = encodedOrErr.reason,
					})
				else
					encodedOrErr.reflectedType = reflectedType
					encodedOrErr.serialized = propertyInfo.Serialized == true
					if readMethod ~= nil then
						encodedOrErr.readMethod = readMethod
					end
					node.properties[propertyName] = encodedOrErr
					ctx.report.propertiesRead += 1
				end
			end
		end
	end

	if ctx.options.IncludeAttributes then
		local okAttrs, attrsOrErr = pcall(function()
			return instance:GetAttributes()
		end)

		if okAttrs and type(attrsOrErr) == "table" then
			for attrName, attrValue in pairs(attrsOrErr) do
				local okEncode, encodedAttr = pcall(function()
					return encodeValue(attrValue, ctx, { propertyName = "@" .. attrName })
				end)

				if okEncode then
					node.attributes[attrName] = encodedAttr
					ctx.report.attributesRead += 1
				else
					push(ctx.report.unsupportedValues, {
						id = id,
						class = instance.ClassName,
						attribute = attrName,
						reason = errorToString(encodedAttr),
					})
				end
			end
		else
			push(ctx.report.failedReads, {
				id = id,
				class = instance.ClassName,
				property = "<attributes>",
				reason = errorToString(attrsOrErr),
			})
		end
	end

	if ctx.options.IncludeTags then
		for _, tag in ipairs(getTagsSafe(instance)) do
			if type(tag) == "string" then
				push(node.tags, tag)
				ctx.report.tagsRead += 1
			end
		end
		table.sort(node.tags)
	end

	for _, child in ipairs(instance:GetChildren()) do
		push(node.children, encodeInstance(child, ctx))
	end

	return node
end

function Codec.Encode(root, options)
	assert(typeof(root) == "Instance", "Codec.Encode(root): root must be an Instance")

	local mergedOptions = mergeOptions(options)
	local report = makeReport("encode")
	local ctx = {
		options = mergedOptions,
		report = report,
		instanceToId = {},
		nextId = 0,
	}

	assignIds(root, ctx)

	local dom = {
		format = Codec.Format,
		version = Codec.Version,
		generatedUnixTime = os.time(),
		root = encodeInstance(root, ctx),
	}

	return dom, report
end

function Codec.EncodeToJSON(root, options)
	local dom, report = Codec.Encode(root, options)

	local ok, jsonOrErr = pcall(function()
		return HttpService:JSONEncode(dom)
	end)

	if not ok then
		error("HttpService:JSONEncode failed: " .. errorToString(jsonOrErr))
	end

	return jsonOrErr, report
end

function Codec.EncodeToJSON_File(root,options)
	local dom,report = Codec.EncodeToJSON(root,options)
	
	local result = Instance.new("Script")
	result.Enabled = false
	result.Name = "JSON Result"
	game:GetService("ScriptEditorService"):UpdateSourceAsync(result,function()
		return dom
	end)
	
	return result,report
end

local function createInstanceForNode(node, ctx)
	local className = node.class or node.ClassName
	assert(type(className) == "string", "DOM node missing class")

	if ctx.options.DeniedClasses[className] then
		error("Class denied by options.DeniedClasses: " .. className)
	end

	if ctx.options.AllowedClasses ~= nil and not ctx.options.AllowedClasses[className] then
		error("Class not present in options.AllowedClasses: " .. className)
	end

	local okNew, instanceOrErr = pcall(function()
		return Instance.new(className)
	end)

	if okNew then
		return instanceOrErr, false
	end

	if className == "Terrain" and ctx.options.UseExistingTerrainForNonCreatable then
		local okTerrain, terrain = pcall(function()
			return workspace.Terrain
		end)
		if okTerrain and terrain ~= nil then
			push(ctx.report.warnings, "Using existing workspace.Terrain for non-creatable Terrain node " .. safeToString(node.id))
			return terrain, true
		end
	end

	if ctx.options.UseExistingServicesForNonCreatable then
		local okService, service = pcall(function()
			return game:GetService(className)
		end)
		if okService and service ~= nil then
			push(ctx.report.warnings, "Using existing service " .. className .. " for non-creatable node " .. safeToString(node.id))
			return service, true
		end
	end

	if ctx.options.AllowFolderFallbackForNonCreatable then
		local folder = Instance.new("Folder")
		folder.Name = "Unsupported_" .. className
		folder:SetAttribute("OriginalClassName", className)
		folder:SetAttribute("CreateError", errorToString(instanceOrErr))
		push(ctx.report.warnings, "Fell back to Folder for non-creatable class " .. className .. ": " .. errorToString(instanceOrErr))
		return folder, false
	end

	error("Could not create class " .. className .. ": " .. errorToString(instanceOrErr))
end

local function createTreePass(node, ctx)
	maybeYield(ctx)

	local instance, isExisting = createInstanceForNode(node, ctx)
	ctx.report.instances += 1

	if node.id ~= nil then
		ctx.idToInstance[node.id] = instance
	end

	local record = {
		node = node,
		instance = instance,
		isExisting = isExisting,
		children = {},
	}
	push(ctx.records, record)

	for _, childNode in ipairs(node.children or {}) do
		maybeYield(ctx)
		local childRecord = createTreePass(childNode, ctx)
		push(record.children, childRecord)
	end

	return record
end

local function recordFailedWrite(ctx, node, propertyName, reason)
	push(ctx.report.failedWrites, {
		id = node.id,
		class = node.class,
		property = propertyName,
		reason = reason,
	})

	if ctx.options.FailOnPropertyError then
		error("Failed to write " .. safeToString(node.class) .. "." .. propertyName .. ": " .. reason)
	end
end

local function reapplyConcreteGuiTransparencyProperties(record, ctx)
	local instance = record.instance
	local node = record.node
	local props = node.properties or {}

	if not isA(instance, "GuiObject") then
		return
	end

	-- Several reflected GUI properties are aliases/aggregates. The only reliable
	-- way to keep text visible is to apply the real concrete transparency fields
	-- one final time after every other reflected property has been attempted.
	for _, propertyName in ipairs(GUI_CONCRETE_TRANSPARENCY_PROPERTIES) do
		maybeYield(ctx)
		local encodedValue = props[propertyName]
		if encodedValue ~= nil then
			local ok, methodOrErr = writeProperty(instance, propertyName, encodedValue, ctx)
			if ok then
				ctx.report.propertiesReapplied += 1
			else
				recordFailedWrite(ctx, node, propertyName, "final concrete transparency reapply failed: " .. methodOrErr)
			end
		end
	end
end

local function applyPropertiesPass(record, ctx)
	maybeYield(ctx)

	local instance = record.instance
	local node = record.node
	local propertyNames = sortNamesForDecode(node.properties or {})

	for _, propertyName in ipairs(propertyNames) do
		maybeYield(ctx)

		local encodedValue = node.properties[propertyName]
		local skipAlias, aliasSkipReason = shouldSkipGuiObjectTransparencyAlias(instance, propertyName, node, ctx)

		if RESERVED_PROPERTIES[propertyName] then
			push(ctx.report.skipped, {
				id = node.id,
				class = node.class,
				property = propertyName,
				reason = "reserved structural property",
			})
		elseif skipAlias then
			push(ctx.report.skipped, {
				id = node.id,
				class = node.class,
				property = propertyName,
				reason = aliasSkipReason,
			})
		elseif valueContainsInstanceReference(encodedValue, ctx) then
			push(ctx.pendingReferenceProperties, {
				record = record,
				property = propertyName,
				value = encodedValue,
			})
		else
			local ok, methodOrErr = writeProperty(instance, propertyName, encodedValue, ctx)
			if ok then
				ctx.report.propertiesWritten += 1
			else
				push(ctx.report.failedWrites, {
					id = node.id,
					class = node.class,
					property = propertyName,
					reason = methodOrErr,
				})

				if ctx.options.FailOnPropertyError then
					error("Failed to write " .. node.class .. "." .. propertyName .. ": " .. methodOrErr)
				end
			end
		end
	end

	reapplyConcreteGuiTransparencyProperties(record, ctx)

	for attrName, encodedAttr in pairs(node.attributes or {}) do
		maybeYield(ctx)

		local okDecode, valueOrErr = pcall(function()
			return decodeValue(encodedAttr, ctx)
		end)

		if okDecode then
			local okAttr, attrErr = pcall(function()
				instance:SetAttribute(attrName, valueOrErr)
			end)

			if okAttr then
				ctx.report.attributesWritten += 1
			else
				push(ctx.report.failedWrites, {
					id = node.id,
					class = node.class,
					attribute = attrName,
					reason = errorToString(attrErr),
				})
			end
		else
			push(ctx.report.failedWrites, {
				id = node.id,
				class = node.class,
				attribute = attrName,
				reason = "decode failed: " .. errorToString(valueOrErr),
			})
		end
	end

	for _, tag in ipairs(node.tags or {}) do
		maybeYield(ctx)

		if type(tag) == "string" then
			if addTagSafe(instance, tag) then
				ctx.report.tagsWritten += 1
			else
				push(ctx.report.failedWrites, {
					id = node.id,
					class = node.class,
					tag = tag,
					reason = "AddTag failed",
				})
			end
		end
	end

	for _, childRecord in ipairs(record.children) do
		maybeYield(ctx)
		applyPropertiesPass(childRecord, ctx)
	end
end

local function parentTreeInternally(record, ctx)
	for _, childRecord in ipairs(record.children) do
		maybeYield(ctx)

		local ok, err = pcall(function()
			childRecord.instance.Parent = record.instance
		end)
		if not ok then
			-- Parent failures are handled by caller's report through a wrapper.
			error(errorToString(err))
		end
		parentTreeInternally(childRecord, ctx)
	end
end

local function applyPendingReferenceProperties(ctx)
	for _, pending in ipairs(ctx.pendingReferenceProperties) do
		maybeYield(ctx)

		local record = pending.record
		local ok, methodOrErr = writeProperty(record.instance, pending.property, pending.value, ctx)

		if ok then
			ctx.report.propertiesWritten += 1
		else
			push(ctx.report.failedWrites, {
				id = record.node.id,
				class = record.node.class,
				property = pending.property,
				reason = methodOrErr,
			})

			if ctx.options.FailOnPropertyError then
				error("Failed to write reference property " .. record.node.class .. "." .. pending.property .. ": " .. methodOrErr)
			end
		end
	end
end

function Codec.Decode(dom, options)
	assert(type(dom) == "table", "Codec.Decode(dom): dom must be a table")
	assert(dom.format == Codec.Format, "Unsupported DOM format: " .. safeToString(dom.format))
	assert(type(dom.root) == "table", "DOM missing root node")

	local mergedOptions = mergeOptions(options)
	local report = makeReport("decode")
	local ctx = {
		options = mergedOptions,
		report = report,
		decodeYieldState = makeDecodeYieldState(mergedOptions, report),
		idToInstance = {},
		records = {},
		pendingReferenceProperties = {},
	}

	local rootRecord = createTreePass(dom.root, ctx)
	applyPropertiesPass(rootRecord, ctx)

	local okParentInternal, parentErr = pcall(function()
		parentTreeInternally(rootRecord, ctx)
	end)
	if not okParentInternal then
		push(report.failedWrites, {
			id = rootRecord.node.id,
			class = rootRecord.node.class,
			property = "<internal parenting>",
			reason = errorToString(parentErr),
		})
		if mergedOptions.FailOnPropertyError then
			error("Internal parenting failed: " .. errorToString(parentErr))
		end
	end

	applyPendingReferenceProperties(ctx)

	if mergedOptions.Parent ~= nil then
		local okParentRoot, rootParentErr = pcall(function()
			rootRecord.instance.Parent = mergedOptions.Parent
		end)

		if not okParentRoot then
			push(report.failedWrites, {
				id = rootRecord.node.id,
				class = rootRecord.node.class,
				property = "Parent",
				reason = errorToString(rootParentErr),
			})
			if mergedOptions.FailOnPropertyError then
				error("Root parenting failed: " .. errorToString(rootParentErr))
			end
		end
	end

	return rootRecord.instance, report
end

function Codec.DecodeFromJSON(json, options)
	assert(type(json) == "string", "Codec.DecodeFromJSON(json): json must be a string")

	local mergedOptions = mergeOptions(options)
	local decodeStartTime = os.clock()

	local ok, domOrErr = pcall(function()
		return HttpService:JSONDecode(json)
	end)

	if not ok then
		error("HttpService:JSONDecode failed: " .. errorToString(domOrErr))
	end

	if mergedOptions.DecodeYieldAfterSeconds ~= false
		and task ~= nil
		and type(task.wait) == "function"
		and os.clock() - decodeStartTime >= mergedOptions.DecodeYieldAfterSeconds then
		task.wait()
	end

	return Codec.Decode(domOrErr, mergedOptions)
end

return Codec
