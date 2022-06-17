# 更新K8S 证书

![build](https://github.com/Ubbo-Sathla/update-k8s-certs/actions/workflows/main.yml/badge.svg)
![release](https://github.com/Ubbo-Sathla/update-k8s-certs/actions/workflows/release.yml/badge.svg)


**操作前请备份好证书，使用该脚本发生任何问题，作者不承担任何责任**

***⚠️目前该脚本只读当前目录config.yaml文件***

> 该脚本适用于kubeadm, 以及自签名ca

---

`原理: 加载已有ca，解析过期证书，根据过期证书内容，更新过期时间，理论适用与自签名的所有证书`

1. 配置文件, 该配置适用与kubeadm部署的K8S集群
2. 新生成的证书及文件将会保存到 kubeConfigDir_时间 目录
3. 对于`kubelet.conf`将会把从文件读取的证书直接写入配置文件
4. 生成`kubelet.conf`文件需要主机上有`ca.crt`,`ca.key`证书

* node 节点配置
```
kubeConfigDir: /etc/kubernetes
CaSign:
  - Name: ca
    CertName: ca.crt
    KeyName: ca.key
    KubeConfigs:
      - kubelet.conf
```
* master 节点配置
```
kubeConfigDir: /etc/kubernetes
CaSign:
  - Name: ca
    CertName: ca.crt
    KeyName: ca.key
    Sign:
      - Name: apiserver
        CertName: apiserver.crt
        KeyName: apiserver.key
      - Name: apiserver-kubelet-client
        CertName: apiserver-kubelet-client.crt
        KeyName: apiserver-kubelet-client.key

    KubeConfigs:
      - admin.conf
      - kubelet.conf
      - controller-manager.conf
      - scheduler.conf

  - Name: front-proxy-ca
    CertName: front-proxy-ca.crt
    KeyName: front-proxy-ca.key
    Sign:
      - Name: front-proxy-client
        CertName: front-proxy-client.crt
        KeyName: front-proxy-client.key

  - Name: etcd/ca
    CertName: etcd/ca.crt
    KeyName: etcd/ca.key
    Sign:
      - Name: apiserver-etcd-client
        CertName: apiserver-etcd-client.crt
        KeyName: apiserver-etcd-client.key
      - Name: etcd/healthcheck-client
        CertName: etcd/healthcheck-client.crt
        KeyName: etcd/healthcheck-client.key
      - Name: etcd/peer
        CertName: etcd/peer.crt
        KeyName: etcd/peer.key
      - Name: etcd/server
        CertName: etcd/server.crt
        KeyName: etcd/server.key
```
