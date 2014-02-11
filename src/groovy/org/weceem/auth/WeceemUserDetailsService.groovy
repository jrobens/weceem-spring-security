package org.weceem.auth

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.userdetails.GrailsUserDetailsService
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.plugins.support.aware.GrailsApplicationAware
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException

import org.apache.commons.logging.LogFactory

/**
 * Implement UserDetailsService
 *
 * http://grails-plugins.github.io/grails-spring-security-core/docs/manual/guide/userDetailsService.html
 */
class WeceemUserDetailsService implements GrailsUserDetailsService, GrailsApplicationAware  {

    def log = LogFactory.getLog("grails.app.service." + WeceemUserDetailsService.name)

    /**
     * Some Spring Security classes (e.g. RoleHierarchyVoter) expect at least one role, so
     * we give a user with no granted roles this one which gets past that restriction but
     * doesn't grant anything.
     */
    static final List NO_ROLES = [new SimpleGrantedAuthority(SpringSecurityUtils.NO_ROLE)]

    static final String[] REQUIRED_MAPPED_FIELDS = ['username', 'password', 'enabled', 'authorities']

    GrailsApplication grailsApplication

    Class domainClass

    Closure detailsMapper

    /*
    void afterPropertiesSet() {

    }
    */

    UserDetails loadUserByUsername(String username, boolean loadRoles)
            throws UsernameNotFoundException {
        return loadUserByUsername(username)
    }

    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        def conf = grailsApplication.config
        /*
        Check to see that found class name is a string.
        | Error 2014-02-02 11:48:57,728 [localhost-startStop-1] ERROR context.GrailsContextLoader  - Error initializing the application: Error creating bean with name 'authenticationUserDetailsService': Cannot resolve reference to bean 'userDetailsService' while setting constructor argument; nested exception is org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'userDetailsService': Invocation of init method failed; nested exception is java.lang.IllegalArgumentException: Dynamic method get<Artefact>Class(artefactName) requires a single String parameter
Message: Error creating bean with name 'authenticationUserDetailsService': Cannot resolve reference to bean 'userDetailsService' while setting constructor argument; nested exception is org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'userDetailsService': Invocation of init method failed; nested exception is java.lang.IllegalArgumentException: Dynamic method get<Artefact>Class(artefactName) requires a single String parameter
         */

        String clsname = conf.grails.plugin.springsecurity.userLookup.userDomainClassName
        def dc = grailsApplication.getDomainClass(clsname)
        if (!dc) {
            throw new IllegalArgumentException("The specified user domain class '$clsname' is not a domain class")
        }

        def mapper = conf.weceem.springsecurity.details.mapper
        detailsMapper = mapper

        if (!(mapper instanceof Closure)) {
            throw new IllegalArgumentException(
                    "Your Config must specify a closure in weceem.springsecurity.details.mapper " +
                            "that maps the domain model to a non-domain object, providing at least: ${REQUIRED_MAPPED_FIELDS}")
        }

        // withTransaction on null object
        // java.lang.NullPointerException: Cannot invoke method withTransaction() on null object
        // org.weceem.auth.WeceemUserDetailsService.loadUserByUsername(WeceemUserDetailsService.groovy:68)

        /*
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            log.error("loadUserByUsername. No transaction manager active.")
            throw new UsernameNotFoundException('User not found', username)
        }

        if (!domainClass || !grailsApplication.isDomainClass(domainClass.getClass())) {
            log.error("loadUserByUsername. Domain class is not specified.")
            throw new UsernameNotFoundException('User not found', username)
        }
        */

        Class<?> User = dc.clazz

        // DomainClass could be found later.
        User.withTransaction { status ->

            def user = User.findByUsername(username)
            if (!user) throw new UsernameNotFoundException('User not found', username)
            def mapperUser = detailsMapper.clone()
            mapperUser.delegate = user
            mapperUser.resolveStrategy = Closure.DELEGATE_FIRST
            def details = mapperUser()

            def requiredDetails = REQUIRED_MAPPED_FIELDS.collect { details[it] }
            if (requiredDetails.find { v -> v == null }) {
                throw new IllegalArgumentException("User details mapper must supply a value for each of the following: ${REQUIRED_MAPPED_FIELDS}")
            }

            Collection<GrantedAuthority>  authorities = details.authorities.collect { new SimpleGrantedAuthority(it.authority) }

            if (log.debugEnabled) {
                log.debug "Returning user details objecting with values: ${requiredDetails.dump()}"
            }
            return new WeceemUserDetails(details.username, details.password, details.enabled, authorities ?: NO_ROLES, details)
        }
    }
}
