# Gen kubeconfig

根据 Kubernetes 集群根证书自动生成具有访问权限的 `kubeconfig` 文件。

该 `kubeconfig` 权限由 `ServiceAccount` 绑定的 `Role` 决定，配置见 `config` 目录。
