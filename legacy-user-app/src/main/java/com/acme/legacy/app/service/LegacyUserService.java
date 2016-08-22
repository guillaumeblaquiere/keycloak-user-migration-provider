/*
 * Copyright 2015 Smartling, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.acme.legacy.app.service;

import com.acme.legacy.app.entity.User;
import com.acme.legacy.app.manager.UserManager;
import com.smartling.keycloak.federation.FederatedUserModel;
import com.smartling.keycloak.federation.FederatedUserService;
import com.smartling.keycloak.federation.UserCredentialsDto;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.ConversionService;
import org.springframework.stereotype.Component;

import javax.ws.rs.Consumes;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

/**
 * Simple JAX-RS based legacy user service.
 */
@Component
@Path("/migration")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class LegacyUserService implements FederatedUserService {
    private static final Logger LOG = LoggerFactory.getLogger(LegacyUserService.class);

    @Autowired
    private ConversionService conversionService;

    @Autowired
    private UserManager userManager;

    private Connection connection;

    public LegacyUserService() {
        LOG.warn("creating me");

        try {

            Class.forName("oracle.jdbc.driver.OracleDriver");

        } catch (ClassNotFoundException e) {

            System.out.println("Where is your Oracle JDBC Driver?");
            e.printStackTrace();
            return;
        }
    }

    private void loadConnexion() {


        try {
            if (connection == null || connection.isClosed())
                connection = DriverManager.getConnection(
                        "jdbc:oracle:thin:@10.1.2.215:1521:fusion", "HR",
                        "HR126");

        } catch (SQLException e) {

            System.out.println("Connection Failed! Check output console");
            e.printStackTrace();
            return;

        }
    }

    @Override
    public FederatedUserModel getUserDetails(String username) {
        loadConnexion();
        User user = null;
        try {
            String sql = "select EMAIL,NAME from pzuser where login = '" + username + "'";
            ResultSet rs = connection.createStatement().executeQuery(sql);

            if (rs.next()) {
                user.setUsername(rs.getString("EMAIL"));
                user.setEmail(rs.getString("EMAIL"));
                user.setEnabled(true);
                user.setFirstName(rs.getString("Name"));
                //user.setLastName();
                Set<String> role = new HashSet<>();
                role.add("accessFusion");
                user.setRoles(role);
                Map<String,List<String>> attributes = new HashMap<>();
                attributes.put("fusionLogin", Arrays.asList(username));
                user.setAttributes(attributes);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return conversionService.convert(user, FederatedUserModel.class);
    }

    @Override
    public Response validateUserExists(String username) {
        loadConnexion();
        String hashedPassword = null;
        try {
            String sql = "select CREDENTIAL from pzuser where login = '" + username + "'";
            ResultSet rs = connection.createStatement().executeQuery(sql);

            if (rs.next()) {
                hashedPassword = rs.getString("CREDENTIAL");
                LOG.info("User {} login exists", username);
            } else {
                LOG.info("User {} login not exists", username);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        Status status = hashedPassword != null ? Status.OK : Status.NOT_FOUND;
        return Response.status(status).entity("").build();
    }

    @Override
    public Response validateLogin(String username, UserCredentialsDto credentials) {
        loadConnexion();
        Status status = Status.UNAUTHORIZED;

        try {
            String sql = "select CREDENTIAL from pzuser where login = '" + username + "'";
            ResultSet rs = connection.createStatement().executeQuery(sql);
            String hashedPassword = null;
            if (rs.next()) {
                hashedPassword = rs.getString("CREDENTIAL");
            }
            if (hashedPassword != null && BCrypt.checkpw(credentials.getPassword(), hashedPassword)) {
                status = Status.OK;
                LOG.info("User {} login valid", username);
            }
            LOG.info("User {} login isn't valid", username);
        } catch (Exception ex) {
            //catch all
            ex.printStackTrace();
            status = Status.UNAUTHORIZED;
            LOG.info("User {} login failed", username);
        }

        return Response.status(status).entity("").build();
    }
}

