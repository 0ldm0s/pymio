# PyMio change log

**Release 1.9.5** - 2024-12-20

**更新内容**

- 临时锁定 flask-socketio 5.4.1
- 增加celery 5.4 的 amqp 支持

**celery with amqp 使用方法**

> 需要注意的是，celery官方疑似不再推荐amqp作为后端使用，应在条件允许的情况下更换为redis。

`CELERY_BROKER_USE_SSL`设置是否使用SSL/TLS，如果需要，则需要指定端口号为`5671`。

`CELERY_RESULT_BACKEND`指定后端处理，如果需要使用旧版的处理逻辑，则用`celery_amqp_backend.AMQPBackend://`，默认应设为`rpc://`。

`CELERY_RESULT_PERSISTENT`设置消息持久化，建议设为禁用。

`CELERY_RESULT_EXCHANGE`固定值，兼容旧版rabbitmq（低于4.0），可不设置。

`CELERY_RESULT_EXCHANGE_TYPE`固定值，兼容旧版rabbitmq（低于4.0），可不设置。

```python
CELERY_BROKER_USE_SSL = True
CELERY_RESULT_BACKEND = "celery_amqp_backend.AMQPBackend://"
CELERY_RESULT_PERSISTENT = False
CELERY_RESULT_EXCHANGE = "celery_result"
CELERY_RESULT_EXCHANGE_TYPE = "direct"
```

连接URI范例（with TLS）

```python
"amqp://{user}:{password}@{host}:5671/{user}"
```

**已知bug**

- celery 使用 amqp 作为 backend 会触发一个 rabbitmq 4.x 的过期功能警告：`transient_nonexcl_queues`，等待包作者更新修复或彻底移除amqp支持，解决方案应优先选择 redis 作为 backend，如无法满足（例如需要通过互联网连接），则应考虑 postgresql。
- 如果禁用`transient_nonexcl_queues`，会导致 celery 无法正常连接rabbitmq。
- flask-socketio 5.5.0 会引发一个错误，临时锁定为 5.4.1。
