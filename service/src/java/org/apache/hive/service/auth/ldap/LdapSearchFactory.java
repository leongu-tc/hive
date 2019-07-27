/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hive.service.auth.ldap;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.sasl.AuthenticationException;
import org.apache.hadoop.hive.conf.HiveConf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A factory for LDAP search objects.
 */
public final class LdapSearchFactory implements DirSearchFactory {

  private static final Logger LOG = LoggerFactory.getLogger(LdapSearchFactory.class);

  private static final String CONNECT_TIME_OUT = "com.sun.jndi.ldap.connect.timeout";

  private static final String READ_TIME_OUT = "com.sun.jndi.ldap.read.timeout";

  private static final String TIME_OUT = "10000";

  /**
   * {@inheritDoc}
   */
  @Override
  public DirSearch getInstance(HiveConf conf, String principal, String password)
      throws AuthenticationException {
    try {
      DirContext ctx = createDirContext(conf, principal, password);
      return new LdapSearch(conf, ctx);
    } catch (NamingException e) {
      LOG.error("Could not connect to the LDAP Server:Authentication failed for principal:" + principal, e);
      throw new AuthenticationException("Error validating LDAP user", e);
    }
  }

  private static DirContext createDirContext(HiveConf conf, String principal, String password)
      throws NamingException {
    Hashtable<String, Object> env = new Hashtable<String, Object>();
    String ldapUrl = conf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_URL);
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, ldapUrl);
    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    env.put(Context.SECURITY_CREDENTIALS, password);
    env.put(Context.SECURITY_PRINCIPAL, principal);
    env.put(CONNECT_TIME_OUT, TIME_OUT);
    env.put(READ_TIME_OUT, TIME_OUT);
    LOG.info("Connecting using principal {} to ldap url {}", principal, ldapUrl);
    return new InitialDirContext(env);
  }
}
