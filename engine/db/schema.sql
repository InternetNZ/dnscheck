-- $Id$

-- DNSCheck Primary Data

/*! SET FOREIGN_KEY_CHECKS=0 */;

CREATE TABLE IF NOT EXISTS `messages` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `tag` varchar(255) NOT NULL default '',
  `arguments` tinyint(3) unsigned NOT NULL default 0,
  `language` varchar(16) NOT NULL default 'en-US',
  `formatstring` varchar(255) default NULL,
  `description` text default NULL,
  PRIMARY KEY  (`id`),
  UNIQUE KEY `langtag` (`tag`,`language`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- source_id should reference an entry in the source table.
-- source_data is some piece of data private to a particular source.
-- It will be copied to the tests table by the dispatcher.
-- fake_parent_glue gives necessary data to run tests on undelegated
-- domains. The content of the field must be nameserver specifikations
-- separated by spaces. Each nameserver is either simply a name, which
-- will be looked up in DNS as usual, or a name, a slash and an IP
-- address. Example: "ns.example.com ns2.example.com/127.0.0.2"

CREATE TABLE IF NOT EXISTS `queue` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `domain` varchar(255) default NULL,
  `priority` tinyint(3) unsigned NOT NULL default '0',
  `inprogress` datetime default NULL,
  `tester_pid` int(10) unsigned NULL,
  `source_id` int(10) unsigned NULL,
  `source_data` varchar(255) NULL,
  `fake_parent_glue` text NULL,
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

CREATE TABLE IF NOT EXISTS `tests` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `domain` varchar(255) NOT NULL default '',
  `begin` datetime default NULL,
  `end` datetime default NULL,
  `count_critical` int(10) unsigned default '0',
  `count_error` int(10) unsigned default '0',
  `count_warning` int(10) unsigned default '0',
  `count_notice` int(10) unsigned default '0',
  `count_info` int(10) unsigned default '0',
  `source_id` int(10) unsigned NULL,
  `source_data` varchar(255) NULL,
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

CREATE TABLE IF NOT EXISTS `results` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `test_id` int(10) unsigned NOT NULL,
  `line` int(10) unsigned NOT NULL,
  `module_id` int(10) unsigned NOT NULL,
  `parent_module_id` int(10) unsigned NOT NULL,
  `timestamp` datetime default NULL,
  `level` varchar(16) default NULL,
  `message` varchar(255) NOT NULL default '',
  `arg0` varchar(255) default NULL,
  `arg1` varchar(255) default NULL,
  `arg2` varchar(255) default NULL,
  `arg3` varchar(255) default NULL,
  `arg4` varchar(255) default NULL,
  `arg5` varchar(255) default NULL,
  `arg6` varchar(255) default NULL,
  `arg7` varchar(255) default NULL,
  `arg8` varchar(255) default NULL,
  `arg9` varchar(255) default NULL,
  PRIMARY KEY  (`id`),
  CONSTRAINT `tests` FOREIGN KEY (`test_id`) REFERENCES `tests` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=ascii;


-- Name Service Providers

CREATE TABLE IF NOT EXISTS `nameservers` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `nsp_id` int(10) unsigned NULL,
  `nameserver` varchar(255) UNIQUE NOT NULL default '',
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

CREATE TABLE IF NOT EXISTS `nsp` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `name` varchar(255) default '',
  `email` varchar(255) default '',
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- Domains and History

CREATE TABLE IF NOT EXISTS `domains` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `domain` varchar(255) NOT NULL default '',
  `last_test` datetime default NULL,
  PRIMARY KEY  (`id`),
  UNIQUE KEY (`domain`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

CREATE TABLE IF NOT EXISTS `delegation_history` (
  `id` int(10) unsigned NOT NULL auto_increment,
  `domain` varchar(255) NOT NULL default '',
  `nameserver` varchar(255) NOT NULL default '',
  PRIMARY KEY  (`id`),
  UNIQUE KEY (`domain`,`nameserver`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

-- Registry is a table to keep track of the registry snapshot used to
-- run an specific scan

CREATE TABLE IF NOT EXISTS `registry` (
    `domain` varchar(255) default NULL,
    `registrar` int(10) unsigned NOT NULL,
    `age` int(10) unsigned NOT NULL,
    `source_id` int(10) unsigned NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Source is supposed to be a list of all sources requesting tests.
-- The recommended procedure is that a program that wants to add
-- tests adds its name and possible some contact information to this table,
-- checks what id number it got and then uses that number when inserting
-- into the queue table and selecting from the tests table.
--
-- The easiest way for a source to use this, is to do an INSERT IGNORE of a
-- string unique for that source and then SELECT the id for that string.
-- For most sources, this need only be done once on startup and then the
-- numeric id can be used to insert into the queue or select from tests.

CREATE TABLE IF NOT EXISTS `source` (
    `id` int(10) unsigned NOT NULL auto_increment,
    `name` varchar(255) NOT NULL,
    `contact` varchar(255),
    PRIMARY KEY (`id`),
    UNIQUE KEY (`name`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
