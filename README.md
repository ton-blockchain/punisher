# What is it
Small slashing script, was created from full mytoncore.py script


# How to use
1. Download the script:
```
wget https://raw.githubusercontent.com/newton-blockchain/punisher/master/punisher.py
```

2. Edit the script, section `fix me` (insert your values):
```
nano punisher.py
```

3. Add the script to crontab (e.g. run every 4 hours):
```
crontab -e
```

4. Done!


# Checking the script
Try running the script manually to see the output. On first launch, the script will check and vote for complaints. When you run it again, the script will tell you that it has already voted.
Also, the script can work very quickly and without any special messages, when the complaints have not yet been created.


