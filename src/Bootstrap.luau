local bootstrap = {}

local HttpService = game:GetService("HttpService")

local base = "http://raw.githubusercontent.com/%s/%s/%s/%s"
local owner = HttpService:UrlEncode("mcarey02005")
local repo = HttpService:UrlEncode("easy_ls")
local branch = HttpService:UrlEncode("main")
local manifestPath = HttpService:UrlEncode("src/Manifest.luau")
local codecPath = HttpService:UrlEncode("src/Codec.luau")

local manifestURL = string.format(
	base,
	owner,
	repo,
	branch,
	manifestPath
)
local codecURL = string.format(
	base,
	owner,
	repo,
	branch,
	codecPath
)

local function p(...)
    if not bootstrap.debugMode then return end

	print(...)
end

function bootstrap.build(coreScript,pluginInstance)
    bootstrap.debugMode = coreScript:GetAttribute("db") or false

    p("Starting EasyLS Build")

	p("Loading content manifest")
	
	local ok, manifest = pcall(function()
        return HttpService:RequestAsync(
            {
                Url=manifestURL,
                Method="GET",
                Headers = {
                    ["Cache-Control"] = bootstrap.debugMode and "no-cache" or nil, -- When sending JSON, set this!
                }
            }
        )
    end)
    if not ok then
        print(`Could not get manifest code at {manifestURL}`)
        error(manifest)
    end
    manifest = loadstring(manifest.Body)()

	p("Manifest loaded")

	p("Checking branch")
	local isProd = true
	if string.match(script.Parent.Name,"Beta") then
		isProd = false
	end
	p("Branch: "..tostring(isProd))

    --//Get plugin version and JSON
    p("Getting plugin version and JSON from manifest")
    local versionData = nil
    if isProd then
        versionData = manifest.getLatestReleased()
    else
        versionData = manifest.getLatestBeta()
    end
    p("Got manifest version data : ",versionData)
    p("Fetching DOM for version")

    if not (versionData and versionData.package) then
        print("No loadable version found for this branch.  Check manifest and branch settings.")
        error("No loadable versiondata found for this branch.  Check manifest and branch settings.")
    end

    local domURL = string.format(
        base,
        owner,
        repo,
        branch,
        HttpService:UrlEncode(versionData.package)
    )
    local ok,dom_json = pcall(function()
        return HttpService:RequestAsync(
            {
                Url=domURL,
                Method="GET",
                Headers = {
			        ["Content-Type"] = "application/json", -- When sending JSON, set this!
                    ["Cache-Control"] = bootstrap.debugMode and "no-cache" or nil, -- When sending JSON, set this!
                }
            }
        )
    end)
    if not ok then
        print(`Could not get DOM JSON at {domURL}`)
        error(dom_json)
    end
    dom_json = dom_json.Body
    p("Got json DOM")

    p("Loading codec")
    local ok,codec = pcall(function()
        return HttpService:RequestAsync(
            {
                Url=codecURL,
                Method="GET",
                Headers = {
                    ["Cache-Control"] = bootstrap.debugMode and "no-cache" or nil, -- When sending JSON, set this!
                }
            }
        )
    end)
    if not ok then
        print(`Could not get codec code at {codecURL}`)
        error(codec)
    end
    codec = loadstring(codec.Body)()
    p("Codec loaded")

	--//build plugin
	p("Ordering build")
	local root,report = codec.DecodeFromJSON(dom_json)
	p("Build complete.  Root folder: ",root)
    p("DOM Construction Report: ",report)

    root.Parent = coreScript.Parent

	p("--","Build Complete","--")

	--//run plugin

	p("Requiring entry point function @ srcFolder/Core")
	local runFunction = require(root.PluginCode.Core)

	p("Got entry point function","Running EasyLS")

	runFunction(pluginInstance)

	p("Entry point executed.  Plugin ready.")
end

return bootstrap