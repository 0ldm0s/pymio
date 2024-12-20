# PyMio change log

**Release 1.9.5** - 2024-12-20

**Update**

- Temporary lock flask-socketio 5.4.1
- Add celery 5.4  amqp support

**How to use celery with amqp**

> It should be noted that the Celery official documentation no longer seems to recommend using AMQP as a backend, and it is advisable to switch to Redis when conditions permit.

`CELERY_BROKER_USE_SSL`Set whether to use SSL/TLS; if required, the port must be specified as `5671`.

`CELERY_RESULT_BACKEND`Specify backend processing. If the old logic is needed, use `celery.amqpbackend://`, with the default set to `rpc://`.

`CELERY_RESULT_PERSISTENT`Set message persistence, it is recommended to disable it.

`CELERY_RESULT_EXCHANGE`Fixed value, compatible with older versions of RabbitMQ (below 4.0), optional.

`CELERY_RESULT_EXCHANGE_TYPE`Fixed value, compatible with older versions of RabbitMQ (below 4.0), optional.

```python
CELERY_BROKER_USE_SSL = True
CELERY_RESULT_BACKEND = "celery_amqp_backend.AMQPBackend://"
CELERY_RESULT_PERSISTENT = False
CELERY_RESULT_EXCHANGE = "celery_result"
CELERY_RESULT_EXCHANGE_TYPE = "direct"
```

Example URI（with TLS）

```python
"amqp://{user}:{password}@{host}:5671/{user}"
```

**Known bug**

- Using AMQP as a backend for Celery triggers the deprecated feature of RabbitMQ 4.x: `transient_nonexcl_queues`. It is advisable to wait for the package author to update and fix this issue or to completely remove AMQP support. The preferred solution should prioritize Redis as the backend. If this is not feasible (for example, if an internet connection is required), then PostgreSQL should be considered.
- Disabling `transient_nonexcl_queues` will cause Celery to be unable to connect to RabbitMQ properly.
- Flask-SocketIO 5.5.0 will trigger an error, temporarily locked to 5.4.1.
