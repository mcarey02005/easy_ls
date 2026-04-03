# easy_ls

Deserializes easyls rbxmx into a DOM using below rules, and dumps it into /src.
- Any instance is treated as a directory by default
- Instances of class "Script" or "ModuleScript" have source ciphertext extracted from "c" attribute, and wrote to */InstanceName.txt
- If "c" attribute doesnt exist, the file is assumed to not depend on the runtime loader, and is skipped.

On plugin run, each encrypted file will use bootstrap to traverse the DOM and resolve its ciphertext.

Path collisions are unhandled.
