## environment\.fortify\.enable



Whether to enable fortify\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## environment\.fortify\.package



The fortify package to use\.



*Type:*
package



*Default:*
` <derivation fortify-static-x86_64-unknown-linux-musl-0.3.1> `



## environment\.fortify\.apps

Declarative fortify apps\.



*Type:*
list of (submodule)



*Default:*
` [ ] `



## environment\.fortify\.apps\.\*\.packages



List of extra packages to install via home-manager\.



*Type:*
list of package



*Default:*
` [ ] `



## environment\.fortify\.apps\.\*\.capability\.dbus



Whether to proxy D-Bus\.



*Type:*
boolean



*Default:*
` true `



## environment\.fortify\.apps\.\*\.capability\.pulse



Whether to share the PulseAudio socket and cookie\.



*Type:*
boolean



*Default:*
` true `



## environment\.fortify\.apps\.\*\.capability\.wayland



Whether to share the Wayland socket\.



*Type:*
boolean



*Default:*
` true `



## environment\.fortify\.apps\.\*\.capability\.x11



Whether to share the X11 socket and allow connection\.



*Type:*
boolean



*Default:*
` false `



## environment\.fortify\.apps\.\*\.command



Command to run as the target user\.
Setting this to null will default command to launcher name\.
Has no effect when script is set\.



*Type:*
null or string



*Default:*
` null `



## environment\.fortify\.apps\.\*\.dbus\.session



D-Bus session bus custom configuration\.
Setting this to null will enable built-in defaults\.



*Type:*
null or (function that evaluates to a(n) anything)



*Default:*
` null `



## environment\.fortify\.apps\.\*\.dbus\.system



D-Bus system bus custom configuration\.
Setting this to null will disable the system bus proxy\.



*Type:*
null or anything



*Default:*
` null `



## environment\.fortify\.apps\.\*\.dev



Whether to enable access to all devices\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## environment\.fortify\.apps\.\*\.devel



Whether to enable debugging-related kernel interfaces\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## environment\.fortify\.apps\.\*\.env



Environment variables to set for the initial process in the sandbox\.



*Type:*
null or (attribute set of string)



*Default:*
` null `



## environment\.fortify\.apps\.\*\.extraConfig



Extra home-manager configuration\.



*Type:*
anything



*Default:*
` { } `



## environment\.fortify\.apps\.\*\.extraPaths



Extra paths to make available to the sandbox\.



*Type:*
list of anything



*Default:*
` [ ] `



## environment\.fortify\.apps\.\*\.gpu



Target process GPU and driver access\.
Setting this to null will enable GPU whenever X or Wayland is enabled\.



*Type:*
null or boolean



*Default:*
` null `



## environment\.fortify\.apps\.\*\.groups



List of groups to inherit from the privileged user\.



*Type:*
list of string



*Default:*
` [ ] `



## environment\.fortify\.apps\.\*\.id



Freedesktop application ID\.



*Type:*
null or string



*Default:*
` null `



## environment\.fortify\.apps\.\*\.insecureWayland



Whether to enable direct access to the Wayland socket\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## environment\.fortify\.apps\.\*\.mapRealUid



Whether to enable mapping to priv-user uid\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## environment\.fortify\.apps\.\*\.multiarch



Whether to enable multiarch kernel-level support\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## environment\.fortify\.apps\.\*\.name



Name of the app’s launcher script\.



*Type:*
string



## environment\.fortify\.apps\.\*\.net



Whether to enable network access\.



*Type:*
boolean



*Default:*
` true `



*Example:*
` true `



## environment\.fortify\.apps\.\*\.nix



Whether to enable nix daemon access\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## environment\.fortify\.apps\.\*\.script



Application launch script\.



*Type:*
null or string



*Default:*
` null `



## environment\.fortify\.apps\.\*\.share



Package containing share files\.
Setting this to null will default package name to wrapper name\.



*Type:*
null or package



*Default:*
` null `



## environment\.fortify\.apps\.\*\.tty



Whether to enable access to the controlling terminal\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## environment\.fortify\.apps\.\*\.userns



Whether to enable user namespace creation\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## environment\.fortify\.apps\.\*\.verbose



Whether to enable launchers with verbose output\.



*Type:*
boolean



*Default:*
` false `



*Example:*
` true `



## environment\.fortify\.fsuPackage



The fsu package to use\.



*Type:*
package



*Default:*
` <derivation fortify-fsu-0.3.1> `



## environment\.fortify\.home-manager



Target user shared home-manager configuration\.



*Type:*
function that evaluates to a(n) function that evaluates to a(n) attribute set of anything



## environment\.fortify\.stateDir



The state directory where app home directories are stored\.



*Type:*
string



## environment\.fortify\.users



Users allowed to spawn fortify apps and their corresponding fortify fid\.



*Type:*
attribute set of integer between 0 and 99 (both inclusive)


