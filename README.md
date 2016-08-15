sender_policy_flattener
=======================

Wut diz?
--------

We had a problem in our organisation that caused our SPF records to become invalid:
When customers computers were querying our SPF records, there were more than 10 after following all of the `include:` remarks.

Solution?

Query them all! and give back just the IP addresses.

How do I use it?
----------------

I've provided a 'settings.json' file with an example configuration.

You put in your zone(s), and the 'includes' that they would normally have in there.

Wanna just put IP Addresses in there? You probably don't need this, and also, you can create a sneaky spf.yourdomain.com record with all your IP declarations anyway, and then add THAT record to your flattener settings.

Once configured, just run the script, and it'll email you something that looks vaguely like this:

![Example screenshot](examples/example.png)

Cool, right?
