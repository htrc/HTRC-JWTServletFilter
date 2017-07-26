/**
 * Copyright 2016 Milinda Pathirage
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.indiana.d2i.htrc.security;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import edu.indiana.d2i.htrc.security.jwt.HOCONTokenVerifierConfiguration;
import edu.indiana.d2i.htrc.security.jwt.api.TokenVerifierConfiguration;
import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class JWTServletFilterConfiguration {

    private static final String CONFIG_JWT = "jwtfilter.jwt";
    private static final String CONFIG_CLAIM_MAPPINGS = "jwtfilter.claim-mappings";

    private final Config config;

    public JWTServletFilterConfiguration(String configFile) {
        this.config = ConfigFactory.parseFile(new File(configFile));
    }

    public Map<String, String> getClaimMappings() {
        if (config.hasPath(CONFIG_CLAIM_MAPPINGS)) {
            Map<String, String> mappings = new HashMap<>();

            config.getConfig(CONFIG_CLAIM_MAPPINGS).entrySet().stream().forEach((entry) -> {

                mappings.put(entry.getKey(), (String) entry.getValue().unwrapped());
            });

            return mappings;
        }

        return Collections.emptyMap();
    }

    public TokenVerifierConfiguration getTokenVerifierConfiguration() {
        if (!config.hasPath(CONFIG_JWT)) {
            throw new RuntimeException(
                "Invalid JWT servlet filter configuration. Missing required configuration: " +
                    CONFIG_JWT);
        }

        return HOCONTokenVerifierConfiguration.createInstance(config.getConfig(CONFIG_JWT));
    }
}
