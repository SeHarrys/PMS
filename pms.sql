CREATE TABLE IF NOT EXISTS `control` (
`id` int(6) NOT NULL,
  `pw_name` char(32) NOT NULL DEFAULT '',
  `pw_domain` char(64) NOT NULL DEFAULT '',
  `pw_passwd` char(40) DEFAULT NULL,
  `pw_uid` int(11) DEFAULT NULL,
  `pw_gid` int(11) DEFAULT NULL,
  `pw_gecos` char(48) DEFAULT NULL,
  `pw_dir` char(160) DEFAULT NULL,
  `pw_shell` char(20) DEFAULT NULL,
  `pw_clear_passwd` char(16) DEFAULT NULL,
  `status` tinyint(4) NOT NULL DEFAULT '1'
) ENGINE=MyISAM AUTO_INCREMENT=35 DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `domains` (
`id` int(4) NOT NULL,
  `dominio` varchar(256) NOT NULL,
  `tipo` int(3) NOT NULL DEFAULT '0',
  `estado` tinyint(4) NOT NULL DEFAULT '0',
  `fecha_alta` datetime NOT NULL,
  `fecha_modifica` datetime NOT NULL,
  `fecha_fin` datetime NOT NULL,
  `postmaster` varchar(256) NOT NULL,
  `alias` varchar(256) NOT NULL
) ENGINE=MyISAM AUTO_INCREMENT=17 DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `filters` (
`id` int(11) NOT NULL,
  `method` varchar(56) NOT NULL,
  `method_arg` varchar(256) NOT NULL,
  `value` varchar(256) NOT NULL,
  `control` int(6) NOT NULL,
  `out` varchar(256) NOT NULL
) ENGINE=MyISAM AUTO_INCREMENT=157 DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `whitelist` (
`id` int(11) NOT NULL,
  `domain` varchar(256) NOT NULL
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;
--
ALTER TABLE `control`
 ADD PRIMARY KEY (`id`), ADD KEY `pw_name` (`pw_name`,`pw_domain`);

ALTER TABLE `domains`
 ADD PRIMARY KEY (`id`);

ALTER TABLE `filters`
 ADD PRIMARY KEY (`id`);

ALTER TABLE `whitelist`
 ADD PRIMARY KEY (`id`);
