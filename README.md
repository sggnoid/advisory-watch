# advisory-watch

Checks Mozilla's security advisories every 15 minutes. When a new Firefox advisory appears, it sends a phone push and opens an issue here.

It reads [mozilla/foundation-security-advisories](https://github.com/mozilla/foundation-security-advisories) one numbered file at a time, and `watch.json` records how far it has got. It sits in its own public repo because Actions minutes are free on public repos.

Advisory text is treated as untrusted. Only validated fields are kept, and nothing is rendered as HTML.

"Exploited in the wild" is a phrase match, because advisories have no field for it. It can fire falsely and it can miss.

## Tests

```
python3 -m unittest discover -s tests
```

## Test alert

Run the `watch` workflow by hand with **Send a test alert** ticked.
