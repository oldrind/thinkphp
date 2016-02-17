<?php
// +----------------------------------------------------------------------
// | ThinkPHP [ WE CAN DO IT JUST THINK IT ]
// +----------------------------------------------------------------------
// | Copyright (c) 2009 http://thinkphp.cn All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: liu21st <liu21st@gmail.com>
// +----------------------------------------------------------------------
namespace Org\Util;

use Think\Db;

/**
 * 基于角色的数据库方式验证类
 */
// 配置文件增加设置
// RBAC_AUTH_ON 是否需要认证
// RBAC_AUTH_TYPE 认证类型
// RBAC_SESSION_KEY 保存RBAC类的SESSION标记
// RBAC_CHECK_MODULE  需要认证模块
// RBAC_ALLOW_MODULE 无需认证模块
// RBAC_DB_DSN  数据库连接DSN
// RBAC_ROLE_TABLE 角色表名称
// RBAC_USER_TABLE 用户角色关系表名称
// RBAC_ACCESS_TABLE 权限表名称
// RBAC_NODE_TABLE 节点表名称
/*
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `think_access` (
  `role_id` smallint(6) unsigned NOT NULL,
  `node_id` smallint(6) unsigned NOT NULL,
  `level` tinyint(1) NOT NULL,
  `module` varchar(50) DEFAULT NULL,
  KEY `groupId` (`role_id`),
  KEY `nodeId` (`node_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `think_node` (
  `id` smallint(6) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(20) NOT NULL,
  `title` varchar(50) DEFAULT NULL,
  `status` tinyint(1) DEFAULT '0',
  `remark` varchar(255) DEFAULT NULL,
  `sort` smallint(6) unsigned DEFAULT NULL,
  `pid` smallint(6) unsigned NOT NULL,
  `level` tinyint(1) unsigned NOT NULL,
  `expression` varchar(500) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `level` (`level`),
  KEY `pid` (`pid`),
  KEY `status` (`status`),
  KEY `name` (`name`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `think_role` (
  `id` smallint(6) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(20) NOT NULL,
  `pid` smallint(6) DEFAULT NULL,
  `status` tinyint(1) unsigned DEFAULT NULL,
  `remark` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `pid` (`pid`),
  KEY `status` (`status`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 ;

CREATE TABLE IF NOT EXISTS `think_role_user` (
  `role_id` smallint(6) unsigned DEFAULT NULL,
  `user_id` int(10) unsigned DEFAULT NULL,
  KEY `group_id` (`role_id`),
  KEY `user_id` (`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
*/

class Rbac
{
    // 默认配置
    private $config = array(
        'RBAC_AUTH_ON'      => true, // 是否开启权限认证
        'RBAC_AUTH_TYPE'    => 1, // 默认认证类型 1:登录认证 2:实时认证
        'RBAC_SESSION_KEY'  => 'RBAC', // 保存RBAC类的SESSION标记
        'RBAC_CHECK_MODULE' => '', // 需要认证模块
        'RBAC_ALLOW_MODULE' => '', // 无需认证模块
        'RBAC_DB_DSN'       => '',  // 数据库连接DSN
        'RBAC_ROLE_TABLE'   => 'role', // 角色表名称
        'RBAC_USER_TABLE'   => 'role_user', // 用户表名称
        'RBAC_ACCESS_TABLE' => 'access', // 权限表名称
        'RBAC_NODE_TABLE'   => 'node', // 节点表名称
    );
    private $administrator = false; // 是否为超级管理员
    private $authId = 0; // 用户id
    private $accessList = null; // 权限列表

    // 保存类实例的静态成员变量
    private static $instance;

    /**
     * 构造函数为private,防止创建对象
     * @param integer $authId 用户id
     * @param boolean $admin 是否为超管
     * @param array $config 配置参数
     */
    private function __construct($authId, $admin = false, $config = null)
    {
        $keys = array_keys($this->config);
        if (!empty($config) && is_array($config)) {
            foreach ($keys as $key) {
                if (isset($config[$key])) {
                    $this->config[$key] = $config[$key];
                }
            }
        } else {
            foreach ($keys as $key) {
                if (!is_null(C($key))) {
                    $this->config[$key] = C($key);
                }
            }
        }
        $this->config['RBAC_CHECK_MODULE'] = is_array($this->config['RBAC_CHECK_MODULE']) ? array_map('strtoupper', $this->config['RBAC_CHECK_MODULE']) : explode(',', strtoupper($this->config['RBAC_CHECK_MODULE']));
        $this->config['RBAC_ALLOW_MODULE'] = is_array($this->config['RBAC_ALLOW_MODULE']) ? array_map('strtoupper', $this->config['RBAC_ALLOW_MODULE']) : explode(',', strtoupper($this->config['RBAC_ALLOW_MODULE']));

        is_numeric($authId) && $this->authId = intval($authId);
        $this->administrator = $admin;
        // 如果不是超级用户并开启了验证
        if (!$this->administrator && $this->config['RBAC_AUTH_ON']) {
            // 如果不是实时验证，保存当前用户的访问权限列表
            if ($this->config['RBAC_AUTH_TYPE'] != 2 || !isset($this->accessList)) {
                $this->accessList = $this->getAccessList($authId);
            }
        }
    }

    /**
     * 类初始化
     * @param integer $authId 用户id
     * @param boolean $admin 是否为超管
     * @param array $config 配置参数
     * @return object
     */
    public static function getInstance($authId, $admin = false, $config = null)
    {
        if (empty($config)) {
            $config = C('RBAC_CONFIG');
        }
        if (!empty($config['RBAC_SESSION_KEY'])) {
            $name = $config['RBAC_SESSION_KEY'];
        } else {
            $name = C('RBAC_SESSION_KEY') ?: 'RBAC';
        }
        if (!isset($_SESSION[$name]) && !(self::$instance instanceof self)) {
            $_SESSION[$name] = self::$instance = new self($authId, $admin, $config);
        } else {
            self::$instance = $_SESSION[$name];
            self::$instance->administrator = $admin;
        }
        return self::$instance;
    }

    // 防止对象被复制
    public function __clone()
    {
        trigger_error('Clone is not allow!', E_USER_ERROR);
    }

    /**
     * 权限认证
     * @param string $action 模块/控制器/方法 或者自定义的规则名
     * @param integer $type 认证模式 1登录 2实时
     * @param string $relation 多条件间关系
     * @param array $replace 用于替换条件参数
     * @return boolean
     */
    public function check($action = NULL, $type = 1, $relation = 'and', $replace = array())
    {
        // 如果关闭了认证或为超级管理员
        if (!$this->config['RBAC_AUTH_ON'] || $this->administrator) {
            return true;
        }
        // 默认为:模块/控制器/方法
        if (is_null($action) || substr_count($action, '/') >= 2) {
            $action = is_null($action) ? array(MODULE_NAME, CONTROLLER_NAME, ACTION_NAME) : explode('/', $action);
            $action = array_map('strtoupper', $action);
            // 如果模块需要认证
            if ($this->checkModule($action)) {
                // 即时验证模式
                if ($type == 2 || $this->config['RBAC_AUTH_TYPE'] == 2 || !isset($this->accessList)) {
                    $map = " and ((node.level=1 and node.name='{$action[0]}')";
                    $map .= " or (node.level=2 and node.name='{$action[1]}')";
                    $map .= " or (node.level=3 and node.name='{$action[2]}'))";
                    // 从数据库中读取
                    $this->accessList = $this->getAccessList($this->authId, $map);
                }
                // 进行权限验证
                if (isset($this->accessList[$action[0]][$action[1]][$action[2]])) {
                    return true;
                }
            }
        } else { // 自定义规则
            $relation = strtolower($relation);
            if (is_string($action)) {
                // 如果有多个规则
                if (false !== strpos($action, ',')) {
                    $action = explode(',', $action);
                } else {
                    $action = array($action);
                }
            }
            // 需要认证的规则
            if ($list = array_diff($action, $this->config['RBAC_ALLOW_MODULE'])) {
                // 如果条件为or则只要有一个规则不需要认正就通过
                if ($relation == 'or' || count($list) < count($action)) {
                    return true;
                }
                // 即时验证模式
                if ($type == 2 || $this->config['RBAC_AUTH_TYPE'] == 2 || !isset($this->accessList)) {
                    $map = ' and node.level=0';
                    $map .= count($list) == 1 ? " and node.name='{$list[0]}'" : " and node.name in('" . implode("','", $list) . "')";
                    // 从数据库中读取
                    $this->accessList = $this->getAccessList($this->authId, $map);
                }
                $flag = array();
                foreach ($list as $name) {
                    // 检查每个规则的权限
                    if (isset($this->accessList[$name])) {
                        // 带有附加的条件
                        if (!empty($this->accessList[$name])) {
                            $condition = $this->accessList[$name];
                            if ($replace && is_array($replace)) {
                                // 参数替换
                                foreach ($replace as $k => $v) {
                                    $condition = str_replace('{' . $k . '}', $v, $condition);
                                }
                            }
                            if (false === strpos(';', $condition)) {
                                @(eval("\$val=(" . $condition . ");"));
                                if (!empty($val) && $relation == 'or') {
                                    return true;
                                }
                                $flag[] = $val;
                            }
                        } else {
                            // 只要满足一个规则就直接通过
                            if ($relation == 'or') {
                                return true;
                            }
                            $flag[] = true;
                        }
                    } else {
                        $flag[] = false;
                    }
                }
                // 条件为and时需要满足所有规则
                if (!empty($flag) && !in_array(false, $flag)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 检查模块是否需要认证
     * @param string $action 模块/控制器/方法
     * @return boolean
     */
    private function checkModule($action)
    {
        $action[2] = implode('/', $action);
        $action[1] = $action[0] . '/' . $action[1];
        if ((!empty($this->config['RBAC_CHECK_MODULE']) && array_intersect($action, $this->config['RBAC_CHECK_MODULE'])) || (!empty($this->config['RBAC_ALLOW_MODULE']) && !array_intersect($action, $this->config['RBAC_ALLOW_MODULE']))) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 取得当前认证号的所有权限列表
     * @param integer $authId 用户ID
     * @param string $map 条件
     * @param array $table RBAC表
     * @return array
     */
    private function getAccessList($authId, $map = '', $tables = null)
    {
        if (is_null($tables)) {
            $prefix = $this->config['RBAC_DB_DSN'] == '' ? C('DB_PREFIX') : '';
            $tables['role'] = $prefix . $this->config['RBAC_ROLE_TABLE'];
            $tables['user'] = $prefix . $this->config['RBAC_USER_TABLE'];
            $tables['access'] = $prefix . $this->config['RBAC_ACCESS_TABLE'];
            $tables['node'] = $prefix . $this->config['RBAC_NODE_TABLE'];
        }
        // Db方式权限数据
        $db = Db::getInstance($this->config['RBAC_DB_DSN']);
        $sql = "select node.id,node.name,node.pid,node.level,node.expression from " .
            $tables['node'] . " as node join " .
            $tables['access'] . " as access on node.id=access.node_id join " .
            $tables['user'] . " as user on access.role_id=user.role_id join " .
            $tables['role'] . " as role on user.role_id=role.id " .
            "where user.user_id='{$authId}' and role.status=1 and node.status=1" . $map;
        $list = $db->query($sql);
        $result = $access = array();
        if ($list) {
            foreach ($list as $v) {
                if ($v['level'] == 0) {
                    $result[strtoupper($v['name'])] = $v['expression'];
                } else {
                    unset($v['expression']);
                    $access[$v['level']][$v['id']] = $v;
                }
            }
            foreach ($access[3] as $k => $v) {
                if (isset($access[2][$v['pid']])) {
                    $pid = $access[2][$v['pid']]['pid'];
                    if (isset($access[1][$pid])) {
                        $array = array();
                        $array[] = $access[1][$pid]['name'];
                        $array[] = $access[2][$v['pid']]['name'];
                        $array[] = $v['name'];
                        $array = array_map('strtoupper', $array);
                        $result[$array[0]][$array[1]][$array[2]] = $k;
                    }
                }
            }
        }
        return $result;
    }
}
