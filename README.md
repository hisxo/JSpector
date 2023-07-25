# JSpector

JSpector is a Burp Suite extension that passively crawls JavaScript files and automatically creates issues with URLs, endpoints and dangerous methods found on the JS files.

![image](https://user-images.githubusercontent.com/16657045/228315561-ee2fa437-5020-45c2-99b2-6ee8cd71f880.png)

## Prerequisites

Before installing JSpector, you need to have Jython installed on Burp Suite.

## Installation

1.  Download [the latest version](https://github.com/hisxo/JSpector/releases) of JSpector
2.  Open Burp Suite and navigate to the `Extensions` tab.
3.  Click the `Add` button in the `Installed` tab.
4.  In the `Extension Details` dialog box, select `Python` as the `Extension Type`.
5.  Click the `Select file` button and navigate to the `JSpector.py`.
6.  Click the `Next` button.
7.  Once the output shows: "JSpector extension loaded successfully", click the `Close` button.

## Usage

- Just navigate through your targets and JSpector will start passively crawl JS files in the background and automatically returns the results on the `Dashboard` tab.
- You can export all the results to the clipboard (_URLs, endpoints and dangerous methods_) with a right click directly on the JS file:

![image](https://user-images.githubusercontent.com/16657045/232149174-04d80248-93ff-42d7-8f0b-e0303b3bc289.png)
