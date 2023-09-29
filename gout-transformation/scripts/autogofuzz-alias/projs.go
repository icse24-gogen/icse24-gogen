package main

func getProjs() map[string]string {
	yamlmap := make(map[string]string)
	yamlmap["std"] = "std_yaml_out_dir"
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

	// purelib

	yamlmap["color"] = "color_yaml_out_dir"
	yamlmap["mysql"] = "mysql_yaml_out_dir"
	yamlmap["buffalo"] = "buffalo_yaml_out_dir"
	yamlmap["govalidator"] = "govalidator_yaml_out_dir"
	yamlmap["gnet"] = "gnet_yaml_out_dir"
	yamlmap["casbin"] = "casbin_yaml_out_dir"
	yamlmap["kit"] = "kit_yaml_out_dir"
	yamlmap["Halfrost-Field"] = "Halfrost-Field_yaml_out_dir"

	return yamlmap
}
