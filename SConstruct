import os
import sys
import platform as _platform

#
#   Command line options and help
#

opts = Variables('build.conf')
opts.AddVariables(('CONF_DIR', """Directory where the Netsukuku configuration files will be installed""", '/etc/netsukuku'),
        ('DATA_DIR', 'Directory to install data files', '/usr/share/netsukuku'),
        ('MAN_DIR',  'Where the manuals will be installed', '/usr/man'),
        ('BIN_DIR' , 'Directory to install the binaries', '/usr/bin'),
        ('PID_DIR',  'Specify location of ntkd.pid file', '/var/run'),
        ('destdir', 'SCons will copy all the files under destdir during installation', '/'),
        EnumVariable('debug', 'build the debug code', 'no',
            allowed_values=('yes', 'no', '1', '0'), map={},
            ignorecase=0),
        EnumVariable('static', 'build statically the binaries', 'no',
            allowed_values=('yes', 'no', '1', '0'), map={},
            ignorecase=0))
opts.Add('CC', 'The C compiler.')
opts.Add('CXX', 'The C++ compiler.')

env = Environment(options=opts, ENV=os.environ, CCFLAGS=' -Wall')

# Added       flag -fcommon for multiple definition of variables
env.Append(CFLAGS=['-fcommon'])     # Per il codice C
env.Append(CXXFLAGS=['-fcommon'])  # Per il codice C++

env['platform'] = _platform.system().lower()
env["CC"] = os.getenv("CC") or env["CC"]
env["CXX"] = os.getenv("CXX") or env["CXX"]
env["ENV"].update(x for x in os.environ.items() if x[0].startswith("CCC_"))

env.Append(CPPPATH=['#src'])
env.Append(LIBPATH=['#src'])
env.Append(CFLAGS=['-g'])

opts.Save('build.conf', env)

Help("""
*** Usage
      'scons' to build the ntkd binary,
      'scons debug=yes' to build the debug version.
      'scons install' to install it in the system.

*** General options
""" + opts.GenerateHelpText(env))

print("====================================================")
print("Compiling Netsukuku for " + env['platform'])
print("====================================================")

Export("env")

# Main Sources
SConscript("#src/SConscript")