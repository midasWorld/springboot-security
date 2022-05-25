package com.prgrms.devcourse.user;

import static com.google.common.base.Preconditions.*;
import static org.apache.commons.lang3.StringUtils.*;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UserService {

	private final UserRepository userRepository;
	private final GroupRepository groupRepository;

	public UserService(UserRepository userRepository, GroupRepository groupRepository) {
		this.userRepository = userRepository;
		this.groupRepository = groupRepository;
	}

	@Transactional(readOnly = true)
	public Optional<User> findByUsername(String username) {
		checkArgument(isNotEmpty(username), "username must be provided.");

		return userRepository.findByUsername(username);
	}

	@Transactional(readOnly = true)
	public Optional<User> findByProviderAndProviderId(String provider, String providerId) {
		checkArgument(isNotEmpty(provider), "provider must be provided.");
		checkArgument(isNotEmpty(providerId), "providerId must be provided.");

		return userRepository.findByProviderAndProviderId(provider, providerId);
	}

	@Transactional
	public User join(OAuth2User oauth2User, String provider) {
		checkArgument(oauth2User != null, "oauth2User must be provided.");
		checkArgument(isNotEmpty(provider), "provider must be provided.");

		String providerId = oauth2User.getName();
		return findByProviderAndProviderId(provider, providerId)
			.map(user -> {
				log.warn("Already exists: {} for provider: {} providerId: {}", user, provider, providerId);
				return user;
			})
			.orElseGet(() -> {
				Map<String, Object> attributes = oauth2User.getAttributes();

				Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");
				checkArgument(properties != null, "OAuth2User properties is empty");

				String nickname = (String) properties.get("nickname");
				String profileImage = (String)properties.get("profile_image");
				Group group = groupRepository.findByName("USER_GROUP")
					.orElseThrow(() -> new IllegalArgumentException("Could not found group for USER_GROUP"));
				return userRepository.save(
					new User(nickname, provider, providerId, profileImage, group)
				);
			});
	}
}
