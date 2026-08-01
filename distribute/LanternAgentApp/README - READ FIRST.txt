LANTERN - HOW TO JOIN
=====================

You do this ONCE. After that the laptop looks after itself.


STEP 1 - Install Tailscale (once, ~1 minute)
--------------------------------------------
Go to https://tailscale.com/download and install it.

You do NOT need a Tailscale account. Do not sign up, do not log in.
Lantern hands the laptop its own key. Just install and close it.

(If you skip this, everything else still works - the shared folder,
encryption, locking. This laptop just will not be on the private network.)


STEP 2 - Put this folder somewhere sensible
-------------------------------------------
Anywhere EXCEPT C:\Lantern. Your Desktop or Documents is perfect.

C:\Lantern is created automatically by the program - that is the shared
folder, and it is a different thing from this one.


STEP 3 - Check config.txt
--------------------------
Open config.txt. It needs two lines, both given to you by whoever sent
you this folder:

    LANTERN_SERVER_URL=https://...
    LANTERN_ENROLLMENT_KEY=...

The enrollment key belongs to your laptop specifically. It works once,
on one machine - after your first run it is locked to this laptop and
cannot be used on any other.


STEP 4 - Double-click "Join Lantern.bat"
-----------------------------------------
A black window opens and stays open. That is normal - it is the agent
running. Leave it open.

Wait for it to say:   Shared folder ready at C:\Lantern

If it says Tailscale needs Administrator rights: close the window,
right-click "Join Lantern.bat", choose "Run as administrator", and
click Yes. You only ever need to do that once.


THAT IS THE WHOLE THING
=======================
You will not be asked to do anything else, ever. When a rental starts
this laptop joins by itself. When it ends it locks by itself.


USING IT
--------
Open C:\Lantern. Drop files in. They appear on everyone else's C:\Lantern
within a few seconds, and their files appear in yours.

Everything in there is encrypted before it leaves your machine. The
server stores it as scrambled blocks and does not hold the key, so it
cannot read your files even if it wanted to.


WHAT YOU WILL SEE LATER
-----------------------
When the rental ends, the files in C:\Lantern stay where they are but
stop opening - same filenames, unreadable contents. That is deliberate,
not a bug. If the rental is extended they come back.

After erasure is confirmed they never come back. The key is gone.


STOPPING AND STARTING
---------------------
Close the black window, or press Ctrl+C. Safe at any time.
Run "Join Lantern.bat" again to pick up where you left off.


LEAVING FOR GOOD
----------------
Deletes your keys and the shared folder from this machine:

    open a terminal in this folder and run:
    lantern-agent.exe leave


WHAT LANTERN CAN AND CANNOT SEE
-------------------------------
Collected:      which laptop this is, whether it is online, whether its
                key is active or destroyed.
Never collected: your file names, your file contents, your browsing,
                your keystrokes, your screen, your location, or your name.
