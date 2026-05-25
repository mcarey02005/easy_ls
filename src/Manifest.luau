--//easyls version manifest w/ helper functions
local api = {}

api = {
	versionManifest = { --/versions listed newest to oldest.  if released=true, public can access.
		{version="v0.9.903",package="versions/0.9.903.json",released=false},
		{version="v0.9.902",package="versions/0.9.902.json",released=false},
		{version="v0.9.901",package="versions/0.9.901.json",released=false},
		{version="v0.9.900",package="versions/0.9.900.json",released=false},
	},	
}

api.getLatestBeta = function()
	return api.versionManifest[1]
end
api.getLatestReleased = function()
	local i = 1
	local ver = api.versionManifest[i]

	while ver and not ver.released do
		i+=1
		ver = next(api.versionManifest,i)
	end

	return ver
end

return api