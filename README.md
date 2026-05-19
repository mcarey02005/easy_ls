# easy_ls

`src/` contains all luau files required by plugin to boot.
Plugin script calls `Bootstrap.luau`, which uses `Manifest.luau` and `Codec.luau` to build the appropriate plugin version.

All of those versions can be found under `versions/`

To add a new version, compile the plugin file to JSON DOM using the codec, put it in versions and name it correctly.  It should be a json file.
Then index it to `src/Manifest.luau`.
Push to to main, and then users should all get update.