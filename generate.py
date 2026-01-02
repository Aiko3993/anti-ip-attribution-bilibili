#!/usr/bin/env python3
# 针对部分网站显示IP归属地的分流规则
# anti-ip-attribution generate.py
# https://github.com/SunsetMkt/anti-ip-attribution
# 从rules.yaml生成配置文件，由Actions调用。
import os
import sys
import git
import yaml
import shutil

def read_yaml(file):
    """读取YAML文件"""
    with open(file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def save_string(string, filename):
    """保存字符串"""
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(string)

def get_git_hash():
    """获取Git提交"""
    try:
        repo = git.Repo(search_parent_directories=True)
        sha = repo.head.object.hexsha
        return str(sha)
    except:
        return "unknown"

def get_head_comment(config, filename="", description=""):
    """获取头部注释"""
    comment = ""
    comment += "# " + config["config"]["description"] + "\n"
    comment += (
        "# "
        + config["config"]["name"]
        + " "
        + filename
        + " "
        + config["config"]["version"]
        + " "
        + get_git_hash()
        + "\n"
    )
    comment += "# " + config["config"]["url"] + "\n"
    comment += "# " + description + "\n"
    return comment

def seprate_comma(string):
    """分割字符串"""
    return string.split(",")

def check_rules(config):
    """检查规则是否有误"""
    rules = config["config"]["rules"]
    for rule in rules:
        rule = rule.strip()
        if not rule:
            continue
        parts = seprate_comma(rule)
        if len(parts) < 2:
            print(f"规则格式错误: {rule}")
            return False
    return True

def classify_rules(rules):
    """分类规则"""
    # buckets[type][policy]
    buckets = {
        "domain_set": {"direct": [], "reject": [], "proxy": []},
        "non_ip": {"direct": [], "reject": [], "proxy": []},
        "ip": {"direct": [], "reject": [], "proxy": []},
        "all": []
    }

    for rule in rules:
        rule = rule.strip()
        if not rule:
            continue
        
        parts = seprate_comma(rule)
        method = parts[0].strip().upper()
        content = parts[1].strip()
        
        # Determine Policy
        policy = "proxy" # Default
        if len(parts) >= 3:
            p = parts[2].strip().upper()
            if "REJECT" in p:
                policy = "reject"
            elif "DIRECT" in p:
                policy = "direct"
        
        # DOMAIN-SET
        if method == "DOMAIN-SUFFIX":
            buckets["domain_set"][policy].append(f".{content}")
        elif method == "DOMAIN":
            buckets["domain_set"][policy].append(content)
            
        # IP Rules
        if method in ["IP-CIDR", "IP-CIDR6", "GEOIP"]:
            buckets["ip"][policy].append(rule)
        else:
            # Non-IP Rules
            buckets["non_ip"][policy].append(rule)
            
        buckets["all"].append(rule)

    return buckets

def generate_files(config):
    """生成统一的规则文件"""
    rules = config["config"]["rules"]
    buckets = classify_rules(rules)
    
    output_dir = "generated"
    if os.path.exists(output_dir):
        # Optional: clear directory or rely on overwrite. 
        # Since we are changing structure, might be good to clean up flat files from previous run if automated.
        # But let's just create new ones.
        pass
    os.makedirs(output_dir, exist_ok=True)

    # Helper to save bucket
    def save_bucket(category_key, policy, content_list, desc_prefix):
        if not content_list:
            return
        
        # Map keys to folder names
        dir_map = {
            "domain_set": "domain-set",
            "non_ip": "non-ip",
            "ip": "ip"
        }
        
        folder_name = dir_map.get(category_key, category_key)
        folder_path = os.path.join(output_dir, folder_name)
        os.makedirs(folder_path, exist_ok=True)
        
        filename = f"{policy}.list"
        full_path = os.path.join(folder_path, filename)
        
        comment = get_head_comment(config, f"{folder_name}/{filename}", f"{desc_prefix} ({policy.upper()})")
        content = comment + "\n".join(content_list)
        save_string(content, full_path)
        print(f"Generated {folder_name}/{filename}")

    # Generate files for each category and policy
    for policy in ["direct", "reject", "proxy"]:
        save_bucket("domain_set", policy, buckets["domain_set"][policy], "纯域名规则集合 (DOMAIN-SET)")
        
        non_ip_clean = [",".join(seprate_comma(r)[:2]) for r in buckets["non_ip"][policy]]
        save_bucket("non_ip", policy, non_ip_clean, "非IP类规则 (Non-IP)")
        
        ip_clean = [",".join(seprate_comma(r)[:2]) for r in buckets["ip"][policy]]
        save_bucket("ip", policy, ip_clean, "IP类规则 (IP)")

    # All rules (fallback)
    filename = "rules.list"
    comment = get_head_comment(config, filename, "全量规则 (All Rules)")
    all_clean = [",".join(seprate_comma(r)[:2]) for r in buckets["all"]]
    content = comment + "\n".join(all_clean)
    save_string(content, os.path.join(output_dir, filename))
    print(f"Generated {filename}")

if __name__ == "__main__":
    config = read_yaml("rules.yaml")
    print("=====================")
    print("开始生成配置文件...")
    print("=====================")
    
    if check_rules(config):
        generate_files(config)
        print("=====================")
        print("生成配置文件完成！")
    else:
        print("规则检查未通过！")
        sys.exit(1)
