#!/usr/bin/env python3
# 针对部分网站显示IP归属地的分流规则
# anti-ip-attribution generate.py
# https://github.com/SunsetMkt/anti-ip-attribution
# 从rules.yaml生成配置文件，由Actions调用。
# 读取文件：
# rules.yaml 配置文件
# parser-header.yaml parser.yaml的生成模板
# 输出文件：
# parser.yaml 适用于Clash for Windows的配置文件预处理功能，详见https://docs.cfw.lbyczf.com/contents/parser.html
# rule-provider.yaml 适用于Clash的Rule Provider功能，详见https://lancellc.gitbook.io/clash/clash-config-file/rule-provider
# rule-provider-direct.yaml rule-provider-proxy.yaml rule-provider-reject.yaml
# surge.list Surge分流规则
import copy
import os
import sys

import git
import yaml


def read_yaml(file):
    """读取YAML文件"""
    with open(file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def save_yaml(config, filename):
    """保存YAML文件"""
    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False)


def get_yaml_string(config):
    """获取YAML字符串"""
    return yaml.dump(config, default_flow_style=False)


def save_string(string, filename):
    """保存字符串"""
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(string)


def get_git_hash():
    """获取Git提交"""
    repo = git.Repo(search_parent_directories=True)
    sha = repo.head.object.hexsha
    return str(sha)


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


def yaml_list(rules):
    """yaml写法转list写法，去掉最后的动作部分"""
    ret = []
    for rule in rules:
        seprated = seprate_comma(rule)
        # 只保留前两个部分 (例如: DOMAIN,example.com 或 IP-CIDR,1.1.1.1/32)
        ret.append(",".join(seprated[:2]))
    return ret


def get_list_string(list):
    return "\n".join(list)


def check_rules(config):
    """检查规则是否有误"""
    rules = config["config"]["rules"]
    # 预期中可用的规则方法
    expected_methods = [
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "IP-CIDR",
        "GEOIP",
        "DST-PORT",
        "IP-CIDR6",
    ]
    # 容易出错的规则方法
    questioned_methods = ["SRC-IP-CIDR", "SRC-PORT", "RULE-SET", "MATCH", "IP6-CIDR"]
    # 预期中可用的规则部分
    expected_rules = ["DIRECT", "REJECT", "no-resolve"]
    # rules中不需要出现IP类关键词，生成脚本会按需自动添加
    should_not_appear_rules = ["IP", "IP归属地"]
    for rule in rules:
        rule = rule.strip()
        print(rule)
        # 检查空行
        if rule == "":
            print("规则空行")
            return False
        else:
            print("非空行")
        # 检查逗号分隔
        length = len(seprate_comma(rule))
        print("length: " + str(length))
        if length == 1:
            print("规则不完整？没有逗号分隔？：" + rule)
            return False
        elif length == 2:
            pass
        elif length == 3:
            pass
        else:
            print("规则有误？逗号分隔超过三个部分：" + rule)
            return False
        # 检查规则方法
        method = seprate_comma(rule)[0]
        print("method: " + method)
        if method not in expected_methods and method not in questioned_methods:
            print("规则方法有误？：" + rule)
            return False
        if method.upper() in questioned_methods:
            print("规则方法有误？" + method + "可能是常见错误：" + rule)
            return False
        if method not in expected_methods and method.upper() in expected_methods:
            print("规则方法未大写？：" + rule)
            return False
        # 检查规则部分
        if length == 3:
            print("length == 3")
            this_rule = seprate_comma(rule)[2]
            print("rule: " + this_rule)
            if this_rule not in expected_rules:
                print("规则有误？" + this_rule + "是预期之外的规则：" + rule)
                return False
            for should_not_appear_rule in should_not_appear_rules:
                if should_not_appear_rule in this_rule.upper():
                    print("规则有误？rules中不需要出现“IP归属地”类规则描述：" + rule)
                    return False
    return True


def generate_parser(config):
    """生成parser.yaml"""
    head = read_yaml(os.path.join("templates", "parser-header.yaml"))
    print(head)
    comment = get_head_comment(
        config,
        "parser.yaml",
        "适用于Clash for Windows的配置文件预处理功能，详见https://docs.cfw.lbyczf.com/contents/parser.html",
    )
    rules = []
    for rule in config["config"]["rules"]:
        rule = rule.strip()
        if len(seprate_comma(rule)) == 2:
            rules.append(rule + ",IP归属地")
        else:
            rules.append(rule)
    head["parsers"][0]["yaml"]["prepend-rules"] = rules
    output = get_yaml_string(head)
    output = comment + output
    save_string(output, os.path.join("generated", "Clash", "parser.yaml"))


def generate_rule_provider(config):
    """生成rule-provider.yaml"""
    comment = get_head_comment(
        config,
        "rule-provider.yaml",
        "适用于Clash의 Rule Provider功能，详见https://lancellc.gitbook.io/clash/clash-config-file/rule-provider",
    )
    # 为了不影响其他软件规则的生成，使用深拷贝
    rules = copy.deepcopy(config["config"]["rules"])

    # https://github.com/SunsetMkt/anti-ip-attribution/issues/23#issuecomment-1223931835
    direct = []
    proxy = []
    reject = []
    for rule in rules:
        if "REJECT" in rule:
            reject.append(rule)
        elif "DIRECT" in rule:
            direct.append(rule)
        else:
            proxy.append(rule)

    # Summary of rules
    print("生成rule-provider.yaml")
    output = {}
    output["payload"] = yaml_list(rules)
    output = comment + get_yaml_string(output)
    save_string(output, os.path.join("generated", "Clash", "rule-provider.yaml"))

    # Direct rules list
    print("生成rule-set-direct.list")
    comment = get_head_comment(config, "rule-set-direct.list", "适用于Clash RULE-SET")
    output = yaml_list(direct)
    output = comment + get_list_string(output)
    save_string(output, os.path.join("generated", "Clash", "rule-set-direct.list"))

    # Proxy rules list
    print("生成rule-set-proxy.list")
    comment = get_head_comment(config, "rule-set-proxy.list", "适用于Clash RULE-SET")
    output = yaml_list(proxy)
    output = comment + get_list_string(output)
    save_string(output, os.path.join("generated", "Clash", "rule-set-proxy.list"))

    # Reject rules list
    print("生成rule-set-reject.list")
    comment = get_head_comment(config, "rule-set-reject.list", "适用于Clash RULE-SET")
    output = yaml_list(reject)
    output = comment + get_list_string(output)
    save_string(output, os.path.join("generated", "Clash", "rule-set-reject.list"))
    # Direct rules
    print("生成rule-provider-direct.yaml")
    comment = get_head_comment(
        config,
        "rule-provider-direct.yaml",
        "适用于Clash的Rule Provider功能，详见https://lancellc.gitbook.io/clash/clash-config-file/rule-provider",
    )
    output = {}
    output["payload"] = yaml_list(direct)
    output = comment + get_yaml_string(output)
    save_string(output, os.path.join("generated", "Clash", "rule-provider-direct.yaml"))
    # Proxy rules
    print("生成rule-provider-proxy.yaml")
    comment = get_head_comment(
        config,
        "rule-provider-proxy.yaml",
        "适用于Clash的Rule Provider功能，详见https://lancellc.gitbook.io/clash/clash-config-file/rule-provider",
    )
    output = {}
    output["payload"] = yaml_list(proxy)
    output = comment + get_yaml_string(output)
    save_string(output, os.path.join("generated", "Clash", "rule-provider-proxy.yaml"))
    # Reject rules
    print("生成rule-provider-reject.yaml")
    comment = get_head_comment(
        config,
        "rule-provider-reject.yaml",
        "适用于Clash的Rule Provider功能，详见https://lancellc.gitbook.io/clash/clash-config-file/rule-provider",
    )
    output = {}
    output["payload"] = yaml_list(reject)
    output = comment + get_yaml_string(output)
    save_string(output, os.path.join("generated", "Clash", "rule-provider-reject.yaml"))


def generate_surge(config):
    """生成surge.list"""
    comment = get_head_comment(config, "surge.list", "Surge分流规则")

    # 为了不影响其他软件规则的生成，使用深拷贝
    rules = copy.deepcopy(config["config"]["rules"])

    # 使用 yaml_list 获取纯净规则 (只有类型和内容，不带动作)
    pure_rules = yaml_list(rules)
    gen_rules = get_list_string(pure_rules)

    output = comment + gen_rules
    save_string(output, os.path.join("generated", "Surge", "surge.list"))


if __name__ == "__main__":
    config = read_yaml("rules.yaml")
    print(get_head_comment(config, "generate.py", "配置文件生成脚本"))
    print("=====================")
    print("开始生成配置文件...")
    print("=====================")
    print(config)
    print("=====================")
    print("检查规则是否有误...")
    if check_rules(config):
        print("规则检查通过！")
        print("=====================")
        print("生成parser.yaml...")
        generate_parser(config)
        print("=====================")
        print("生成rule-provider.yaml...")
        generate_rule_provider(config)
        print("=====================")
        print("生成surge.list...")
        generate_surge(config)
        print("=====================")
        print("生成配置文件完成！")
    else:
        print("规则检查未通过！")
        print("=====================")
        print("请检查规则是否有误！")
        print("生成配置文件失败！")
        sys.exit(1)
