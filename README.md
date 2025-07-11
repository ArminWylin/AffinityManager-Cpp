# **AffinityManager-Cpp**

A lightweight, efficient Windows service designed to optimize CPU performance on modern hybrid processors (like Intel's P-cores and E-cores) by managing process affinities and power settings.

## **Overview**

AffinityManager is a background service that automatically assigns demanding applications (like games) to your powerful Performance-cores (P-cores) while relegating background tasks to your energy-efficient Efficiency-cores (E-cores). This ensures maximum performance for your games while preventing background chatter from causing stutters or performance loss.

This project is written in native C++ for minimal performance overhead and uses the official Windows API for maximum compatibility and stability.

## **Key Features**

* **Automatic Process Affinity:** Dynamically assigns processes to P-cores or E-cores based on user-defined lists.  
* **E-Core Frequency Control:** When a game is launched, the service can adjust the "Maximum processor frequency" setting in your active power plan, a feature particularly effective on certain Intel CPUs for dedicating more power and thermal headroom to the P-cores.  
* **Persistent Affinity:** Includes a "watcher" thread that ensures games stay on their assigned cores, even if the game itself tries to change its own affinity.  
* **Graceful Cleanup:** Automatically restores all original affinity and power settings when the service is stopped or the computer is shut down.  
* **Extremely Lightweight:** The service is event-driven and uses virtually zero CPU resources while idle, only acting when a process starts or stops.

## **Installation**

To install AffinityManager, you will need to use the included install.bat script.

1. **Get the Project Files:**  
   * Click the green \< \> Code button on the main repository page.  
   * Select **"Download ZIP"**.  
   * Extract the contents of the .zip file to a folder on your computer.  
2. **Compile the Executable (If Needed):**  
   * The AffinityManager.exe file is included in the repository. However, if you don't trust the pre-compiled file or have made changes to the code, you must compile it.  
   * **Prerequisites:** You must have the **MinGW-w64** C++ compiler installed and added to your system's PATH.  
   * Right-click on install.bat and select **"Run as administrator"**.  
   * Choose option **3** to compile the executable.  
3. **Install the Service:**  
   * Ensure AffinityManager.exe is in the same folder as the script.  
   * Right-click on install.bat and select **"Run as administrator"**.  
   * In the menu that appears, choose option **1** to install the service.

The service will now be installed and will start automatically with Windows.

## **How to Use**

The behavior of AffinityManager is controlled by two simple text files located in C:\\ProgramData\\AffinityManager\\:

* games.txt: Add the executable names of your games to this file (e.g., helldivers2.exe), one per line. Processes in this list will be assigned to your P-cores.  
* background.txt: Add the executable names of background applications to this file (e.g., spotify.exe). Processes in this list will be assigned to your E-cores.

The service automatically detects process names in a case-insensitive manner, so you don't need to worry about capitalization (e.g., RDR2.exe and rdr2.exe are treated the same).

## **How It Works**

The service operates using a combination of modern Windows APIs:

1. **WMI (Windows Management Instrumentation):** The service subscribes to process creation and termination events. This is highly efficient as the service remains dormant until the OS sends a notification.  
2. **PowerProf API:** When a game from games.txt is launched, the service modifies the "Maximum processor frequency" setting of your *currently active* power plan. When the last game closes, it restores the setting to its original value.  
3. **Tool Help Library:** Used to get a list of currently running processes on service startup to apply settings immediately.  
4. **Affinity Watcher Thread:** A low-priority background thread runs every 5 seconds to ensure that managed game processes have not changed their own affinity, re-applying the P-core mask if necessary.

## **Building from Source**

If you wish to compile the project manually without using the installer script, you can use the following command with g++:

g++ \-o AffinityManager.exe main.cpp \-municode \-static \-lstdc++ \-lole32 \-loleaut32 \-lwbemuuid \-lpowrprof

## **License**

This project is licensed under the MIT License.