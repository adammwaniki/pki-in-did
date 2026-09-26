walt.id `wallet-api2` configuration, copied from the image with three changes:

* `publicBaseUrl` points at the service's name on the demo network, not `localhost`.
* `wallet2-persistence` is enabled and pointed at `/data`, a mounted volume.
* `auth` is left off: this demonstration has one holder and no user accounts.

It is checked in so the demonstration is reproducible, and so any change is visible in a diff
rather than being a property of whichever image tag happened to be pulled.
