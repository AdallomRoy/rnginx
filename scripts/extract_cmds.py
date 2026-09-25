import re, sys, glob, os
# Extract ngx_command_t entries from C module files: returns dict module_var -> [(name, flags)]
files = sys.argv[1:]
entry_re = re.compile(r'\{\s*ngx_string\("([^"]+)"\)\s*,\s*([A-Z0-9_|\s\n]+?)\s*,', re.S)
mod_re = re.compile(r'^ngx_module_t\s+(ngx_\w+)\s*=', re.M)
cmds_re = re.compile(r'static\s+ngx_command_t\s+(\w+)\s*\[\]\s*=\s*\{(.*?)\n\};', re.S)
for f in files:
    src = open(f).read()
    mods = mod_re.findall(src)
    for cname, body in cmds_re.findall(src):
        entries = entry_re.findall(body)
        # module name: match by prefix
        modname = None
        for m in mods:
            if cname.startswith(m.replace('_module','')):
                modname = m
        if modname is None and mods:
            modname = mods[0]
        print("MODULE", modname or cname, os.path.basename(f))
        for name, flags in entries:
            flags = re.sub(r'\s+', '', flags)
            print("  ", name, flags)
