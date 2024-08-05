package com.example.kimhabspringldap.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.stereotype.Service;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

@Service
@Slf4j
public class LdapUserService {

    @Autowired
    private LdapTemplate ldapTemplate;
    public List<Map<String, Object>> getAllUsers() {
        String searchBase = ""; // Use the root base DN
        //   String filter = "(objectClass=inetOrgPerson)"; // Filter for user objects
        String filter = "(objectClass=top)";

        List<Map<String, Object>> users = ldapTemplate.search(
                searchBase,
                filter,
                (AttributesMapper<Map<String, Object>>) attrs -> {
                    Map<String, Object> user = new HashMap<>();
                    NamingEnumeration<String> ids = attrs.getIDs();
                    while (ids.hasMore()) {
                        String id = ids.next();
                        user.put(id, attrs.get(id).get());
                    }
                    return user;
                }
        );
        log.info("count ldap users: {}", users.size());
        log.info("ldap user: {}", users);

        return users;
    }

    public List<Map<String, Object>> findByUsername(String username) {
        String searchBase = ""; // Root base
        String filter = "(uid=" + username + ")"; // Searching by uid

        List<Map<String, Object>> users = ldapTemplate.search(
                searchBase,
                filter,
                (AttributesMapper<Map<String, Object>>) attrs -> {
                    Map<String, Object> user = new HashMap<>();
                    NamingEnumeration<String> ids = attrs.getIDs();
                    while (ids.hasMore()) {
                        String id = ids.next();
                        user.put(id, attrs.get(id).get());
                    }
                    return user;
                }
        );

        if (users.isEmpty()) {
            log.info("User ldap not found: {}", username);
        } else {
            log.info("User ldap found : {}", users);
        }
        return users;
    }

    public Map<String, Object> findByUsername1(String username) {
        // Define the LDAP query
        var ldapQuery = query()
                //  .base("ou=people,dc=example,dc=com") // Adjust based on your LDAP structure
                .base("") // root
                .where("uid").is(username);

        // Fetch user data from LDAP
        Map<String, Object> ldapUser = new HashMap<>();

        ldapTemplate.search(ldapQuery.base(), ldapQuery.filter().encode(), new AttributesMapper<Object>() {
                    @Override
                    public Object mapFromAttributes(Attributes attrs) throws NamingException {
                        NamingEnumeration<String> attributeNames = attrs.getIDs();
                        while (attributeNames.hasMore()) {
                            String attributeName = attributeNames.next();
                            log.info("attributeName: {}", attributeName);
                            ldapUser.put(attributeName, attrs.get(attributeName).get());
                        }

                        ldapUser.put("group",getGroupsByUid(username));
                        return ldapUser;
                    }
                }
        );
        log.info("LDAP user found: {}", ldapUser);

        return ldapUser;
    }

    public boolean authenticate(String username, String password) {
        try {
            LdapQuery query = query()
                    .base("")
                    .where("uid").is(username);

            // Attempt to bind with the provided credentials
            ldapTemplate.authenticate(query, password);
            log.info("Authentication successful: " + username);
            return true; // Authentication successful
        } catch (Exception e) {
            // Log the exception if needed
            log.info("Authentication failed for user: " + username);
            e.printStackTrace();
            return false; // Authentication failed
        }
    }

    public List<String> getGroupsByUid(String uid) {
     //   uid = "kimhab";
        LdapQuery query = query()
                .base("dc=springframework,dc=org")
                .where("objectClass").is("groupOfUniqueNames")
                .and("uniqueMember").is("uid=" + uid + ",ou=people,dc=springframework,dc=org");

        return ldapTemplate.search(query, (AttributesMapper<String>) attrs -> {
            try {
                var getAtt = attrs.get("cn").get().toString();
                log.info("attribute: {}", getAtt);
                return attrs.get("cn").get().toString();
            } catch (NamingException e) {
                e.printStackTrace();
                return null;
            }
        });
    }
}
