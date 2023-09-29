package main

import (
	"os"

	"jkl/gout-transformation/pkg/transstruct"
)

func getProjs() map[string]string {
	yamlmap := make(map[string]string)
	yamlmap["std"] = "std_yaml_out_dir"
	// yamlmap["std"] = "std_yaml_fatal"
	yamlmap["traefik"] = "traefik_yaml_out_dir"
	yamlmap["gitea"] = "gitea_yaml_out_dir"
	yamlmap["rclone"] = "rclone_yaml_out_dir"
	yamlmap["gin"] = "gin_yaml_out_dir"
	yamlmap["syncthing"] = "syncthing_yaml_out_dir"
	yamlmap["fzf"] = "fzf_yaml_out_dir"
	yamlmap["kubernetes"] = "kubernetes_yaml_out_dir" // unfuzzed

	yamlmap["hugo"] = "hugo_yaml_out_dir"
	yamlmap["compose"] = "compose_yaml_out_dir"

	yamlmap["frp"] = "frp_yaml_out_dir"
	yamlmap["cobra"] = "cobra_yaml_out_dir"
	yamlmap["beego"] = "beego_yaml_out_dir"
	yamlmap["caddy"] = "caddy_yaml_out_dir"
	yamlmap["minio"] = "minio_yaml_out_dir"
	yamlmap["cobra"] = "cobra_yaml_out_dir"
	yamlmap["go-ethereum"] = "go-ethereum_yaml_out_dir"

	yamlmap["gogs"] = "gogs_yaml_out_dir"
	yamlmap["etcd"] = "etcd_yaml_out_dir"

	return yamlmap
}

func fileExists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

var AGlobalVar int = 5

func AssignGlobal() {
	AGlobalVar = transstruct.GetInt(5)
}

func FuzzTestGlobal(data []byte) int {
	AssignGlobal()

	// original code in fuzz func

	return 1
}
