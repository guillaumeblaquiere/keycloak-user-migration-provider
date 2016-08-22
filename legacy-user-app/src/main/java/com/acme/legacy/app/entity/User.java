package com.acme.legacy.app.entity;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Represents an overly simplified user entity in the legacy system.
 *
 * @author Scott Rossillo
 */
public class User implements Serializable
{
    private String email;
    private String firstName;
    private String lastName;
    private String username;
    private String password;
    private String salt;
    private boolean emailVerified;
    private boolean enabled;
    private Set<String> roles;

    private Map<String,List<String>> attributes;

    public User()
    {
    }

    public String getEmail()
    {
        return email;
    }

    public void setEmail(String email)
    {
        this.email = email;
    }

    public String getFirstName()
    {
        return firstName;
    }

    public void setFirstName(String firstName)
    {
        this.firstName = firstName;
    }

    public String getLastName()
    {
        return lastName;
    }

    public void setLastName(String lastName)
    {
        this.lastName = lastName;
    }

    public String getUsername()
    {
        return username;
    }

    public void setUsername(String username)
    {
        this.username = username;
    }

    public String getPassword()
    {
        return password;
    }

    public void setPassword(String password)
    {
        this.password = password;
    }

    public String getSalt()
    {
        return salt;
    }

    public void setSalt(String salt)
    {
        this.salt = salt;
    }

    public boolean isEmailVerified()
    {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified)
    {
        this.emailVerified = emailVerified;
    }

    public boolean isEnabled()
    {
        return enabled;
    }

    public void setEnabled(boolean enabled)
    {
        this.enabled = enabled;
    }

    public Set<String> getRoles()
    {
        return roles;
    }

    public void setRoles(Set<String> roles)
    {
        this.roles = roles;
    }

    public Map<String, List<String>> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, List<String>> attributes) {
        this.attributes = attributes;
    }
}
