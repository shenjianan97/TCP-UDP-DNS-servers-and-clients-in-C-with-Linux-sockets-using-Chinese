# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/clion-2018.1.3/bin/cmake/bin/cmake

# The command to remove a file.
RM = /opt/clion-2018.1.3/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/home/shenjianan/文档/DNS/root server"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/home/shenjianan/文档/DNS/root server/cmake-build-debug"

# Include any dependencies generated for this target.
include CMakeFiles/root_server.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/root_server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/root_server.dir/flags.make

CMakeFiles/root_server.dir/RootServer.c.o: CMakeFiles/root_server.dir/flags.make
CMakeFiles/root_server.dir/RootServer.c.o: ../RootServer.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/shenjianan/文档/DNS/root server/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/root_server.dir/RootServer.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/root_server.dir/RootServer.c.o   -c "/home/shenjianan/文档/DNS/root server/RootServer.c"

CMakeFiles/root_server.dir/RootServer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/root_server.dir/RootServer.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/shenjianan/文档/DNS/root server/RootServer.c" > CMakeFiles/root_server.dir/RootServer.c.i

CMakeFiles/root_server.dir/RootServer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/root_server.dir/RootServer.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/shenjianan/文档/DNS/root server/RootServer.c" -o CMakeFiles/root_server.dir/RootServer.c.s

CMakeFiles/root_server.dir/RootServer.c.o.requires:

.PHONY : CMakeFiles/root_server.dir/RootServer.c.o.requires

CMakeFiles/root_server.dir/RootServer.c.o.provides: CMakeFiles/root_server.dir/RootServer.c.o.requires
	$(MAKE) -f CMakeFiles/root_server.dir/build.make CMakeFiles/root_server.dir/RootServer.c.o.provides.build
.PHONY : CMakeFiles/root_server.dir/RootServer.c.o.provides

CMakeFiles/root_server.dir/RootServer.c.o.provides.build: CMakeFiles/root_server.dir/RootServer.c.o


# Object files for target root_server
root_server_OBJECTS = \
"CMakeFiles/root_server.dir/RootServer.c.o"

# External object files for target root_server
root_server_EXTERNAL_OBJECTS =

root_server: CMakeFiles/root_server.dir/RootServer.c.o
root_server: CMakeFiles/root_server.dir/build.make
root_server: CMakeFiles/root_server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="/home/shenjianan/文档/DNS/root server/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable root_server"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/root_server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/root_server.dir/build: root_server

.PHONY : CMakeFiles/root_server.dir/build

CMakeFiles/root_server.dir/requires: CMakeFiles/root_server.dir/RootServer.c.o.requires

.PHONY : CMakeFiles/root_server.dir/requires

CMakeFiles/root_server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/root_server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/root_server.dir/clean

CMakeFiles/root_server.dir/depend:
	cd "/home/shenjianan/文档/DNS/root server/cmake-build-debug" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/home/shenjianan/文档/DNS/root server" "/home/shenjianan/文档/DNS/root server" "/home/shenjianan/文档/DNS/root server/cmake-build-debug" "/home/shenjianan/文档/DNS/root server/cmake-build-debug" "/home/shenjianan/文档/DNS/root server/cmake-build-debug/CMakeFiles/root_server.dir/DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/root_server.dir/depend

