# Punisher

This script implements receiving complaints about idle or cheating validators, checking complaints and voting for complaints to fine such validators.

This script is used by validators that, for some reason, do not use [mytonctrl](https://github.com/igroman787/mytonctrl).

If you are using mytonctrl (recommended) you do not need to use this script, as the complete slashing process is already built into mytonctrl.

Note that identifying idle or cheating validators and submitting a complaint for such validators is not implemented in the script and it is assumed that this is done by validators using mytonctrl.

This single file script has no dependencies and can be easily reviewed.

Slashing process documentation: [TIP-13](https://github.com/newton-blockchain/TIPs/issues/13), [TIP-14](https://github.com/newton-blockchain/TIPs/issues/14).


# How to use
1. Download the script:
```
wget https://raw.githubusercontent.com/newton-blockchain/punisher/master/punisher.py
```

2. Edit the script parameters, section `fix me` (insert your values):
```
nano punisher.py
```

3. Make the script executable:
```
chmod 755 punisher.py
```

4. Now you can run the script
```
./punisher.py
```

5. Add the script to crontab:
```
crontab -e
```
then add line
```
5       */4     *       *       *       /path/to/punisher.py >/tmp/punisher.out 2>&1
```
(run script every 4 hours and write output to /tmp/punisher.out file

# Checking the script
Try running the script manually to see the output. On first launch, the script will check and vote for complaints. When you run it again, the script will tell you that it has already voted.
Also, the script can work very quickly and without any special messages, when the complaints have not yet been created.


