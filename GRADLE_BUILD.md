# Composite Build
The **Cryptimeleon** libraries, except for **Math** all depend on at least one of the other libraries.
Often times, when developing for example **Craco**, you might also be doing some changes to **Math**.
To include these changes faster, we make extensive use of Gradle`s [composite build](https://docs.gradle.org/current/userguide/composite_builds.html) feature.
To make this easier to use, we have a composite build script contained in ``settings.gradle`` that decides when to enable composite builds and when not.
It also serves to enable composite builds on the Travis CI.

## Default Script Behaviour
By default, the script will automatically clone **Cryptimeleon** dependencies that are not stored in the local file system yet.
It clones them to the same folder that the top-level folder of the library being built is contained in.
Furthermore, it checks that the branch names match. 
If the library is on branch ``branch1`` and a dependency is on ``branch2``, the script will complain and tell you to checkout out branch ``branch1`` in the dependency's git.
If no such branch exists, the library will instead want to use the ``master`` branch.

You can customize this behaviour via the properties detailed in the following section.

## Customizing the Script via Properties
The composite build script can be customized via the following properties. 
The parameters can be set via the ``gradle.properties`` file or set via command line as detailed [here](https://docs.gradle.org/current/userguide/build_environment.html). 

- ``useCurrentBranch``: If defined (any value), will cause the composite build to use the currently
    checked out branch of the dependencies.
- ``checkoutIfCloned``: If defined (any value), will automatically check out the corresponding
    dependency branch (branch with same name) given that the dependency was freshly cloned.
    Used by the Travis CI to automatically switch to the right dependency branch for the build.
    
An example ``gradle.properties`` file:
```
useCurrentBranch=""
```
Here, ``useCurrentBranch`` is enabled by giving it an empty String value.

