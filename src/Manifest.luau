--//easyls version manifest w/ helper functions
local api = {}

api = {
	versionManifest = { --/versions listed newest to oldest.  if released=true, public can access.
		{version="v1.0.008",package="versions/1.0.008.json",released=false},
		{version="v1.0.007",package="versions/1.0.007.json",released=true},
		{version="v1.0.006",package="versions/1.0.006.json",released=false},
		{version="v1.0.005",package="versions/1.0.005.json",released=false},
		{version="v1.0.004",package="versions/1.0.004.json",released=true},
		{version="v1.0.003",package="versions/1.0.003.json",released=false}, --compiler/luraph bug
		{version="v1.0.002",package="versions/1.0.002.json",released=true},
		{version="v1.0.001",package="versions/1.0.001.json",released=true},
		{version="v1.0.000",package="versions/1.0.000.json",released=true},
		{version="v0.9.911",package="versions/0.9.911.json",released=false},
		{version="v0.9.910",package="versions/0.9.910.json",released=false},
		{version="v0.9.909",package="versions/0.9.909.json",released=false},
		{version="v0.9.908",package="versions/0.9.908.json",released=false},
		{version="v0.9.907",package="versions/0.9.907.json",released=false},
		{version="v0.9.906",package="versions/0.9.906.json",released=false},
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
		i,ver = next(api.versionManifest,i)
	end

	return ver
end

return api