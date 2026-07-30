HOW TO JOIN
-----------
1. Put this whole folder ANYWHERE except C:\Lantern - e.g. your Desktop,
   or Documents. Do not rename it to "Lantern" and put it at the C: drive
   root. (C:\Lantern gets created automatically by the program itself -
   that is the shared folder, not this program.)
2. Double-click "Join Lantern.bat".
3. Click Yes on the one Windows permission popup.
4. Wait for the window to say "Shared folder ready at C:\Lantern".
5. Open C:\Lantern (a normal folder, separate from this one) - that is
   where you drop files to share them, and where files from other people
   will appear automatically.

Do not touch config.txt unless someone gives you a different join code.

TO STOP: close this window, or press Ctrl+C. Safe to do anytime - just
run "Join Lantern.bat" again later to pick back up where you left off.

TO LEAVE FOR GOOD (deletes your keys and the shared folder on this
machine): open a terminal in this folder and run:
    lantern-agent.exe leave
