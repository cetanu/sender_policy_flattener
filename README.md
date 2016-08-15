sender_policy_flattener
=======================

Wut diz?
--------

We had a problem in our organisation that caused our SPF records to become invalid:

When customers computers were querying our SPF records, there were more than 10 lookups required after following all of the `include:` remarks.

Solution? Query them ourselves, and create a much more condense list of SPF records.

But wait... What if the upstream records change?
------------------------------------------------

Part of what the script does is that it creates a `sums.json` file that keeps track of the last list of IP Addresses that your combination of SPF records had.

When the hashsum of your IP Addresses changes, it will send out an email (or just dump HTML if it can't find an email server) with a handy diff & BIND format for viewing what has changed, and promptly updating it.

How do I use it?
----------------

I've provided a `settings.json` file with an example configuration.

You put in your zone(s), and the 'includes' that they would normally have in there. Just like I've done with google, and so on.

**Wanna just put straight IP Addresses in there?** You can create a sneaky `spf.yourdomain.com` record with all your IP declarations in there instead, and then add THAT record to your flattener `settings.json`.

Once configured (Don't forget your email address, and email server), you'll need the following:

Prereqs
-------

Python 3 is preferred, but Python 2 might work (this has been tested on 3.5.2)

3rd party modules:

* netaddr
* dnspython (or dnspython3)

just run the script with `python sender_policy_flattener.py` in the same directory as your sums and settings files, and it'll email you something that looks vaguely like this:

![Example screenshot](example/example.png)

Cool, right?
