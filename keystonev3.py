#!/usr/bin/python
import sys
import argparse
import logging
import json
import os.path
from keystoneclient.v3 import client as ksclient


KEYSTONE_ADMIN = 'ADMIN'


class MultiConfig(object):
    """
    Encapsulates different sources of config (command line args and
    a config file), and provides a single access method to them which
    gives precedence to command line args. This class could be sub-classed
    to provide dedicated accessor methods for specific configuration parameters
    """

    # pass confFile name, rather than a configParser, so that we can hide
    # the choice of config file syntax and parser
    # inside this class to enable future change.
    def __init__(self, confFile, args=None):
        """
        confFile will be read for config parameters.
        args should be a dict
        """
        self.args = args
        if (not self.args):
            self.args = {}
        self.parser = None
        if confFile:
            self.parser = self._createConfigParser(confFile)

    def _createConfigParser(self, confFile):
        import ConfigParser

        parser = ConfigParser.SafeConfigParser()
        try:
            logging.info("Reading config from: " + confFile)
            fp = open(confFile)
            parser.readfp(fp)
            fp.close()
        except IOError:
            logging.warn("Config file not found" + confFile)
            raise
        return parser

    def get(self, section, key):
        """
        A general purpose method for accessing config parameters.
        First attempts to get value for key from the argParser (if any).
        If that results in a None value, then attempt to get value from
        (section, key) in config file parser."""
        val = None
        if ((self.args != None) and key in self.args):
            val = self.args[key]
            logging.debug(
                "get (" + str(section) + "," + key + ") from args = " + str(
                    val))
        if (val == None and self.parser and section
            and self.parser.has_option(section, key)):
            val = self.parser.get(section, key)
            logging.debug("get (" + str(
                section) + "," + key + ") from config file = " + str(val))
        return val

    def printAll(self):
        print self.args
        for section in self.parser.sections():
            for item in self.parser.items(section):
                print "" + section + " : " + str(item)


class BaseConfig(MultiConfig):
    """
    define our config parameters and provide some dedicated accessor methods.
    """

    # define config parameter keys...
    CONFIG_FILE = "configFile"
    COMMAND = "command"
    GENERAL_SECTION = "general"
    VERBOSITY = "verbosity"

    PROXY_SECTION = "proxy"
    PROXY = "proxy"

    CLUSTERS_SECTION = 'clusters'
    DEFAULT_CLUSTER = 'default_cluster'
    CLUSTER_NAME = 'cluster'
    IDENTITY_SECTION = "identity"
    IDENTITY_URL = "os_endpoint"
    IDENTITY_SERVICE = "identityService"
    MGMT_USERNAME = 'mgmt_username'
    MGMT_HOSTNAME = 'mgmt_hostname'
    ENDPOINT_SELECT_KEY = 'endpoint_select_key'
    ENDPOINT_SELECT_VAL = 'endpoint_select_val'
    OBJSTORE_URL = 'objstoreUrl'


    # helper methods to avoid using the inherited get(section, key) method
    @property
    def command(self):
        return self.get(None, self.COMMAND)

    @property
    def proxy(self):
        return self.get(self.PROXY_SECTION, self.PROXY)

    def _get_cluster_section(self, cluster_name=None):
        '''
        Get config file section for a cluster_name. Use either supplied
        cluster_name, or find it in CLI args,or use the default cluster_name.
        '''
        key = self.CLUSTER_NAME
        if (cluster_name is None and (self.args != None) and key in self.args):
            cluster_name = self.args[key]
        cluster_section = None
        if cluster_name is None:
            if self.parser.has_option(self.CLUSTERS_SECTION,
                                      self.DEFAULT_CLUSTER):
                cluster_section = self.parser.get(self.CLUSTERS_SECTION,
                                                  self.DEFAULT_CLUSTER)
            else:
                # for backwards compatibility, fall back to root level
                # identity section
                cluster_section = self.IDENTITY_SECTION
        if (cluster_name and self.parser.has_option(self.CLUSTERS_SECTION,
                                                    cluster_name)):
            cluster_section = self.parser.get(self.CLUSTERS_SECTION,
                                              cluster_name)
        logging.debug('_get_cluster_section() <- %s' % cluster_section)
        return cluster_section

    def _get_identity_parameter(self, key, cluster_name=None,
                                raise_error=True):
        '''Get an id service parameter. First looks in command line args, then
        looks inside a config file cluster section.'''
        val = None
        if ((self.args != None) and key in self.args):
            val = self.args[key]
        if not val:
            section = self._get_cluster_section(cluster_name)
            if (section and self.parser.has_option(section, key)):
                val = self.parser.get(section, key)
        logging.debug('_get_identity_parameter(%s) <- %s' % (key, val))
        if not val and raise_error:
            raise RuntimeError("Missing config parameter: %s" % key)
        return val

    def identityUrl(self, cluster_name=None):
        return self._get_identity_parameter(self.IDENTITY_URL, cluster_name)


    @property
    def verbosity(self):
        return self.get(self.GENERAL_SECTION, self.VERBOSITY)


class KeystoneConfig(BaseConfig):
    """Extend Config class to define our config parameters
    and provide some dedicated accessor methods to them."""

    USERNAME = 'os_username'
    USER_ID = 'os_user_id'
    PASSWORD = 'os_password'
    USER_DOMAIN_NAME = 'os_user_domain_name'
    USER_DOMAIN_ID = 'os_user_domain_id'
    PROJECT_NAME = "os_project_name"
    PROJECT_DOMAIN_NAME = 'os_project_domain_name'
    PROJECT_DOMAIN_ID = 'os_project_domain_id'
    PROJECT_ID = "os_project_id"
    DOMAIN_NAME = "os_domain_name"
    DOMAIN_ID = "os_domain_id"
    DESCRIPTION = "os_description"
    ENTITY_NAME = "entity_name"
    ROLE_NAME = "os_role_name"
    ROLE_ID = "os_role_id"
    TOKEN = "os_token"

    @property
    def user_name(self):
        return self.get(None, self.USERNAME)

    @property
    def user_id(self):
        return self.get(None, self.USER_ID)

    @property
    def user_domain_name(self):
        return self.get(None, self.USER_DOMAIN_NAME)

    @property
    def user_domain_id(self):
        return self.get(None, self.USER_DOMAIN_ID)

    @property
    def domain_name(self):
        return self.get(None, self.DOMAIN_NAME)

    @property
    def domain_id(self):
        return self.get(None, self.DOMAIN_ID)

    @property
    def password(self):
        return self.get(None, self.PASSWORD)

    @property
    def project_name(self):
        return self.get(None, self.PROJECT_NAME)

    @property
    def project_domain_name(self):
        return self.get(None, self.PROJECT_DOMAIN_NAME)

    @property
    def project_domain_id(self):
        return self.get(None, self.PROJECT_DOMAIN_ID)

    @property
    def project_id(self):
        return self.get(None, self.PROJECT_ID)

    @property
    def description(self):
        return self.get(None, self.DESCRIPTION)

    @property
    def entity_name(self):
        return self.get(None, self.ENTITY_NAME)

    @property
    def role_name(self):
        return self.get(None, self.ROLE_NAME)

    @property
    def role_id(self):
        return self.get(None, self.ROLE_ID)

    @property
    def token(self):
        return self.get(None, self.TOKEN)


class ClientException(Exception):
    pass


def _get_keystone_client(config):
    token = config.token if config.token else KEYSTONE_ADMIN
    ks = ksclient.Client(token=token, endpoint=config.identityUrl())
    return ks


def role_list(config):
    ks = _get_keystone_client(config)
    user, key = _resolve_user(ks, config)
    project, key = _resolve_project(ks, config)
    user_id = user.id if user else None
    proj_id = project.id if project else None
    dom, key = _resolve_domain(ks, config)
    dom_id = dom.id if dom else None
    items = ks.roles.list(user=user_id, project=proj_id, domain=dom_id)
    for item in items:
        print '%s (%s)' % (item.name, item.id)


def role_create(config):
    ks = _get_keystone_client(config)
    result = ks.roles.create(config.role_name)
    print result.id


def domain_list(config):
    ks = _get_keystone_client(config)
    items = ks.domains.list()
    for item in items:
        print '%s (%s)' % (item.name, item.id)


def _do_resolve_domain(ks, id=None, name=None):
    domain = None
    if id:
        key = id
        try:
            domain = ks.domains.get(key)
        except:
            pass
    else:
        key = name
        domains = ks.domains.list()
        for d in domains:
            if d.name == key:
                domain = d
                break
    return domain, key


def _resolve_domain(ks, config):
    domain = None
    if config.domain_id:
        key = config.domain_id
        try:
            domain = ks.domains.get(key)
        except:
            pass
    else:
        key = config.domain_name
        domains = ks.domains.list()
        for d in domains:
            if d.name == key:
                domain = d
                break
    return domain, key


def _resolve_user_domain(ks, config):
    domain = None
    if config.user_domain_id:
        key = config.user_domain_id
        try:
            domain = ks.domains.get(key)
        except:
            pass
    else:
        key = config.user_domain_name
        domains = ks.domains.list()
        for d in domains:
            if d.name == key:
                domain = d
                break
    return domain, key


def _resolve_project_domain(ks, config):
    domain = None
    if config.project_domain_id:
        key = config.project_domain_id
        try:
            domain = ks.domains.get(key)
        except:
            pass
    else:
        key = config.project_domain_name
        domains = ks.domains.list()
        for d in domains:
            if d.name == key:
                domain = d
                break
    return domain, key


def _resolve_role(ks, config):
    role = None
    if config.role_id:
        key = config.role_id
        try:
            role = ks.roles.get(key)
        except:
            pass
    else:
        key = config.role_name
        roles = ks.roles.list()
        for r in roles:
            if r.name == key:
                role = r
                break
    return role, key


def _resolve_project(ks, config):
    project = None
    if config.project_id:
        print 'resolve project using id %s' % config.project_id
        key = config.project_id
        try:
            project = ks.projects.get(key)
        except Exception as e:
            print 'Exception %s' % e
            pass
    else:
        key = config.project_name
        dom, _ = _resolve_project_domain(ks, config)
        if dom is None:
            dom, _ = _resolve_domain(ks, config)
        dom_id = dom.id if dom else None
        projects = ks.projects.list(domain=dom_id)
        for p in projects:
            if p.name == key:
                project = p
                break
    return project, key


def _resolve_user(ks, config):
    user = None
    if config.user_id:
        key = config.user_id
        try:
            user = ks.users.get(key)
        except:
            pass
    else:
        key = config.user_name
        dom, _ = _resolve_user_domain(ks, config)
        if dom is None:
            dom, _ = _resolve_domain(ks, config)
        dom_id = dom.id if dom else None
        users = ks.users.list(domain=dom_id)
        for u in users:
            if u.name == key:
                user = u
                break
    return user, key


def _get_domain_map(ks):
    results = ks.domains.list()
    return dict((i.id, i.name) for i in results)


def domain_create(config):
    ks = _get_keystone_client(config)
    result = ks.domains.create(config.domain_name)
    print 'Created domain: %s (%s)' % (result.name, result.id)


def domain_delete(config):
    ks = _get_keystone_client(config)
    dom, key = _resolve_domain(ks, config)
    if not dom:
        raise ClientException("Domain %s not found" % key)
    if dom.id == 'default':
        raise ClientException('Cannot delete default domain')
    ks.domains.update(dom.id, enabled=False)
    ks.domains.delete(dom.id)
    print 'Deleted domain: %s (%s)' % (config.domain_name, dom.id)


def project_create(config):
    ks = _get_keystone_client(config)
    dom, key = _resolve_project_domain(ks, config)
    dom_id = dom.id if dom else None
    proj = ks.projects.create(config.project_name, dom_id,
                              config.description, True)
    try:
        domain = ks.domains.get(proj.domain_id)
        d_name = domain.name
        d_id = domain.id
    except Exception:
        d_name = d_id = 'non-existent'
    print('Created project_name %s (%s) in domain %s (%s)'
          % (proj.name, proj.id, d_name, d_id))


def project_delete(config):
    ks = _get_keystone_client(config)
    proj, key = _resolve_project(ks, config)
    if proj:
        try:
            domain = ks.domains.get(proj.domain_id)
            d_name = domain.name
            d_id = domain.id
        except Exception:
            d_name = d_id = 'non-existent'
        ks.projects.delete(proj.id)
        print('Deleted project_name %s (%s) from domain %s (%s)'
              % (proj.name, proj.id, d_name, d_id))
    else:
        print('Error: Project %s not resolved ' % key)


def _get_proj_map(ks, domain_id='default'):
    projects = ks.projects.list()
    return dict((p.id, p.name) for p in projects)


def project_list(config):
    ks = _get_keystone_client(config)
    dom, key = _resolve_project_domain(ks, config)
    dom_id = dom.id if dom else None
    items = ks.projects.list(domain=dom_id)
    domain_map = _get_domain_map(ks)
    for item in items:
        domain = domain_map.get(item.domain_id)
        state = 'enabled' if item.enabled else 'disabled'
        print('%s (%s) in domain %s (%s) %s'
              % (item.name, item.id, domain, item.domain_id, state))


def user_create(config):
    ks = _get_keystone_client(config)
    #     user, key = _resolve_user(ks, config)
    #     if user:
    #         raise ClientException('User %s exists' % key)
    dom, _ = _resolve_user_domain(ks, config)
    dom_id = dom.id if dom else None
    proj, _ = _resolve_project(ks, config)
    proj_id = proj.id if proj else None
    result = ks.users.create(config.user_name, domain=dom_id,
                             password=config.password,
                             default_project=proj_id)
    print result.id


def user_role_add_raw(config):
    ks = _get_keystone_client(config)
    if config.domain_id:
        ks.roles.grant(config.role_id, user=config.user_id,
                       domain=config.domain_id)
    elif config.project_id:
        ks.roles.grant(config.role_id, user=config.user_id,
                       project=config.project_id)
    else:
        raise ClientException('Project ID or domain ID required')


def user_role_add(config):
    ks = _get_keystone_client(config)
    proj, key = _resolve_project(ks, config)
    dom, key = _resolve_domain(ks, config)
    if not proj and not dom:
        raise ClientException('Project or domain required %s' % key)
    dom_id = dom.id if dom else None
    proj_id = proj.id if proj else None
    user, key = _resolve_user(ks, config)
    if not user:
        raise ClientException('User %s not found' % key)
    role, key = _resolve_role(ks, config)
    if not role:
        raise ClientException('Role %s not found' % key)
    ks.roles.grant(role.id, user=user.id, domain=dom_id, project=proj_id)


def user_role_delete(config):
    ks = _get_keystone_client(config)
    proj, key = _resolve_project(ks, config)
    if not proj:
        raise ClientException('Project %s not found' % key)
    user, key = _resolve_user(ks, config)
    if not user:
        raise ClientException('User %s not found' % key)
    role, key = _resolve_role(ks, config)
    if not role:
        raise ClientException('Role %s not found' % key)
    ks.roles.revoke(role.id, user=user.id, project=proj.id)


def user_delete(config):
    ks = _get_keystone_client(config)
    user, key = _resolve_user(ks, config)
    if user:
        ks.users.delete(user.id)
        domain = ks.domains.get(user.domain_id)
        print('Deleted user %s (%s) from domain %s (%s)'
              % (user.name, user.id, domain.name, domain.id))
    else:
        print('Error: User %s not resolved in %s:%s'
              % (key, config.user_domain_name, config.project_name))


def user_update(config):
    ks = _get_keystone_client(config)
    user, key = _resolve_user(ks, config)
    if user:
        ks.users.update(user.id, password=config.password)
        domain = ks.domains.get(user.domain_id)
        print('Updated user %s (%s) from domain %s (%s)'
              % (user.name, user.id, domain.name, domain.id))
    else:
        print('Error: User %s not resolved in %s:%s'
              % (key, config.user_domain_name, config.project_name))


def user_get(config):
    ks = _get_keystone_client(config)
    user, key = _resolve_user(ks, config)
    if user:
        proj_id = getattr(user, 'default_project_id', None)
        if proj_id:
            proj = ks.projects.get(proj_id)
            proj_name = proj.name
        else:
            proj_id = proj_name = 'unassigned'
        dom_id = getattr(user, 'domain_id', None)
        if dom_id:
            dom = ks.domains.get(dom_id)
            dom_name = dom.name
        else:
            dom_id = dom_name = 'unassigned'
        state = 'enabled' if user.enabled else 'disabled'
        print('User    %s (%s)\nProject %s (%s)\nDomain  %s (%s)\n%s'
              % (user.name, user.id, proj_name, proj_id,
                 dom_name, dom_id, state))
    else:
        print('Error: User %s not resolved in %s:%s'
              % (
        config.user_name, config.user_domain_name, config.project_name))


def user_list(config):
    ks = _get_keystone_client(config)
    dom, _ = _resolve_user_domain(ks, config)
    dom_id = dom.id if dom else None
    proj_map = _get_proj_map(ks, config.user_domain_name)
    dom_map = _get_domain_map(ks)
    users = ks.users.list(domain=dom_id)
    for u in users:
        domain = dom_map[u.domain_id]
        proj_id = getattr(u, 'default_project_id', None)
        proj = proj_map.get(proj_id, 'non-existent')
        print('%s (%s) in %s (%s) dflt proj:%s (%s)'
              % (u.name, u.id, domain, u.domain_id, proj, proj_id,))


def token_get(config):
    kwargs = {'password': config.password,
              'auth_url': config.identityUrl()}
    if config.user_id:
        kwargs['user_id'] = config.user_id
    else:
        kwargs['username'] = config.user_name
        kwargs['user_domain_name'] = config.user_domain_name

    kwargs['project_id'] = config.project_id
    kwargs['project_name'] = config.project_name
    kwargs['project_domain_name'] = config.project_domain_name
    kwargs['domain_name'] = config.domain_name
    print 'kwargs %s' % kwargs
    ks = ksclient.Client(**kwargs)
    print ks.auth_token
    catalog = ks.service_catalog.catalog
    print json.dumps(catalog, sort_keys=True, indent=4)


def _setup_user(ks, user_name, domain_id, password):
    conf = {'os_username': user_name,
            'os_user_domain_id': domain_id}
    user, key = _resolve_user(ks, KeystoneConfig(None, conf))
    if user:
        print 'User %s exists' % user.name
    else:
        user = ks.users.create(name=user_name, domain=domain_id,
                               password=password)
        print 'Created user %s' % user.name
    return user.id


def _setup_project(ks, project_name, domain_id):
    conf = {'os_project_name': project_name,
            'os_project_domain_id': domain_id}
    proj, key = _resolve_project(ks, KeystoneConfig(None, conf))
    if proj:
        print 'Project %s exists' % proj.name
    else:
        proj = ks.projects.create(name=project_name, domain=domain_id)
        print 'Created project %s' % proj.name
    return proj.id


def _setup_role(ks, role_name):
    conf = {'os_role_name': role_name}
    role, key = _resolve_role(ks, KeystoneConfig(None, conf))
    if role:
        print 'Role %s exists' % role.name
    else:
        role = ks.projects.create(name=role_name)
        print 'Created role %s' % role.name
    return role.id


def _setup_domain(ks, domain_name):
    conf = {'os_domain_name': domain_name}
    dom, key = _resolve_domain(ks, KeystoneConfig(None, conf))
    if dom:
        print 'Domain %s exists' % dom.name
    else:
        dom = ks.domains.create(domain_name)
        print 'Created domain %s' % dom.name
    return dom.id


def _user_role_list(ks, user, user_id, project, project_id):
    roles = ks.roles.list(user=user_id, project=project_id)
    for role in roles:
        print 'User %s granted role %s for project %s' % (
        user, role.name, project)


def setup_test_env(config):
    role = 'admin'
    test_domain = config.domain_name
    user1 = 'tester'
    user2 = 'tester2'
    project1 = 'test'
    project2 = 'test2'
    password = 'testing2'

    ks = _get_keystone_client(config)

    dom_id = _setup_domain(ks, test_domain)
    role_id = _setup_role(ks, role)
    user1_id = _setup_user(ks, user1, dom_id, password)
    proj1_id = _setup_project(ks, project1, dom_id)
    ks.roles.grant(role_id, user=user1_id, project=proj1_id)
    user2_id = _setup_user(ks, user2, dom_id, password)
    proj2_id = _setup_project(ks, project2, dom_id)
    ks.roles.grant(role_id, user=user2_id, project=proj2_id)

    _user_role_list(ks, user1, user1_id, project1, proj1_id)
    _user_role_list(ks, user2, user2_id, project2, proj2_id)


class ParserFactory(object):
    def __init__(self):
        common_parser = argparse.ArgumentParser(add_help=False)
        common_parser.add_argument("-v", "--" + KeystoneConfig.VERBOSITY,
                                   help="Increase verbosity",
                                   action="count")
        common_parser.add_argument("-c", "--" + KeystoneConfig.CONFIG_FILE,
                                   help="Config file")
        common_parser.add_argument('-i', "--" + KeystoneConfig.CLUSTER_NAME,
                                   help="Name of swift service instance, used \
                                   to select from config file cluster \
                                   specifications.")
        self._add_arg(common_parser, KeystoneConfig.IDENTITY_URL)
        self._add_arg(common_parser, KeystoneConfig.TOKEN)
        # top level parser acts as a container for all sub-command parsers
        self.parser = argparse.ArgumentParser()
        self.subparsers = self.parser.add_subparsers(help="sub-command help")
        self.common_parser = common_parser

    def _add_arg_variations(self, parser, arg, required=False):
        var1 = arg.replace('-', '_')
        var2 = arg.replace('_', '-')
        if (var1 != var2):
            group = parser.add_mutually_exclusive_group(required=required)
            group.add_argument('--' + var1)
            group.add_argument('--' + var2)
        else:
            parser.add_argument('--' + arg, required=required)

    def _add_arg(self, parser, arg, required=False):
        if isinstance(arg, list):
            group = parser.add_mutually_exclusive_group(required=required)
            for a in arg:
                self._add_arg_variations(group, a)
        else:
            self._add_arg_variations(parser, arg, required=required)

    def add_parser(self, subcommand, func,
                   parents=[], required=[], optional=[]):
        parent_parsers = [self.common_parser] + parents
        parser = self.subparsers.add_parser(subcommand,
                                            parents=parent_parsers)
        parser.set_defaults(func=func)
        for arg in required:
            self._add_arg(parser, arg, True)
        for arg in optional:
            self._add_arg(parser, arg, False)

    def parse_args(self):
        args = self.parser.parse_args()
        return args


def _create_arg_parser():
    user_args = [KeystoneConfig.USERNAME, KeystoneConfig.USER_ID]
    project_args = [KeystoneConfig.PROJECT_NAME, KeystoneConfig.PROJECT_ID]
    domain_args = [KeystoneConfig.DOMAIN_NAME, KeystoneConfig.DOMAIN_ID]
    user_domain_args = [KeystoneConfig.USER_DOMAIN_NAME,
                        KeystoneConfig.USER_DOMAIN_ID]
    project_domain_args = [KeystoneConfig.PROJECT_DOMAIN_NAME,
                           KeystoneConfig.PROJECT_DOMAIN_ID]
    role_args = [KeystoneConfig.ROLE_ID, KeystoneConfig.ROLE_NAME]
    parser = ParserFactory()
    parser.add_parser('domain-list', domain_list)
    parser.add_parser('domain-create', domain_create,
                      required=[KeystoneConfig.DOMAIN_NAME])
    parser.add_parser('domain-delete', domain_delete,
                      required=[KeystoneConfig.DOMAIN_NAME])
    parser.add_parser('project-create', project_create,
                      required=[KeystoneConfig.PROJECT_NAME],
                      optional=project_domain_args)
    parser.add_parser('project-delete', project_delete,
                      required=[KeystoneConfig.PROJECT_NAME],
                      optional=project_domain_args)
    parser.add_parser('project-list', project_list,
                      optional=project_domain_args)
    parser.add_parser('tenant-create', project_create,
                      required=[KeystoneConfig.PROJECT_NAME],
                      optional=project_domain_args)
    parser.add_parser('tenant-delete', project_delete,
                      required=[KeystoneConfig.PROJECT_NAME],
                      optional=project_domain_args)
    parser.add_parser('tenant-list', project_list,
                      optional=project_domain_args)
    parser.add_parser('user-create', user_create,
                      required=[KeystoneConfig.USERNAME,
                                KeystoneConfig.PASSWORD],
                      optional=[user_domain_args, project_domain_args,
                                project_args])
    parser.add_parser('user-delete', user_delete,
                      required=[user_args],
                      optional=user_domain_args)
    parser.add_parser('user-list', user_list,
                      optional=[user_domain_args, project_domain_args])
    parser.add_parser('user-role-add', user_role_add,
                      required=[user_args, role_args],
                      optional=[project_args, user_domain_args,
                                project_domain_args, domain_args])
    parser.add_parser('user-role-add-raw', user_role_add_raw,
                      required=[KeystoneConfig.USER_ID,
                                KeystoneConfig.ROLE_ID],
                      optional=[KeystoneConfig.DOMAIN_ID,
                                KeystoneConfig.PROJECT_ID])
    parser.add_parser('user-role-delete', user_role_delete,
                      required=[user_args, role_args, project_args],
                      optional=[user_domain_args, project_domain_args])
    parser.add_parser('user-update', user_update,
                      required=[user_args, KeystoneConfig.PASSWORD],
                      optional=user_domain_args)
    parser.add_parser('user-get', user_get,
                      required=[user_args],
                      optional=user_domain_args)
    parser.add_parser('role-create', role_create,
                      required=[KeystoneConfig.ROLE_NAME],
                      optional=[KeystoneConfig.DOMAIN_ID,
                                KeystoneConfig.PROJECT_ID])
    parser.add_parser('role-list', role_list,
                      optional=[project_domain_args, user_domain_args,
                                user_args, project_args, domain_args])
    parser.add_parser('token-get', token_get,
                      required=[user_args, KeystoneConfig.PASSWORD],
                      optional=[user_domain_args, project_args,
                                project_domain_args, domain_args])
    parser.add_parser('setup-test-env', setup_test_env,
                      required=[domain_args])

    return parser.parse_args()


def _set_log_level(verbosity):
    if (verbosity == None):
        logLevel = logging.WARN
    elif (int(verbosity) == 1):
        logLevel = logging.INFO
    elif (int(verbosity) >= 2):
        logLevel = logging.DEBUG
    else:
        logLevel = logging.WARN
    # default root logger
    logging.getLogger().setLevel(logLevel)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == 'just_do_it':
        setup_test_env()

    args = _create_arg_parser()
    # set initial log level here
    _set_log_level(args.verbosity)

    try:
        config_file = args.configFile
        if (config_file == None):
            home = os.path.expanduser("~")
            if os.path.exists("default_client.conf"):
                config_file = "default_client.conf"
            elif os.path.exists("%s/hyper_client.conf_XXX" % home):
                config_file = "%s/hyper_client.conf_XXX" % home
        config = KeystoneConfig(config_file, vars(args))
    except IOError:
        print("Failed to load config")
    # set log level again in case specified in config file
    _set_log_level(config.verbosity)

    try:
        args.func(config)
    except ClientException as e:
        print "Error:", e.message
    except Exception as e:
        import traceback

        print "Error:", e.message
        traceback.print_exc()


if __name__ == "__main__":
    main()

