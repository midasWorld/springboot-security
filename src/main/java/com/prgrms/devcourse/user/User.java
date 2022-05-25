package com.prgrms.devcourse.user;

import static com.google.common.base.Preconditions.*;
import static org.apache.commons.lang3.StringUtils.*;

import java.util.Optional;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@ToString
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "users")
@Entity
public class User {

	@Id @GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	private String username;
	private String provider;
	private String providerId;

	private String profileImage;

	@ManyToOne
	@JoinColumn(name = "group_id")
	Group group;

	public User(String username, String provider, String providerId, String profileImage, Group group) {
		checkArgument(isNotEmpty(username), "username must be provided.");
		checkArgument(isNotEmpty(provider), "provider must be provided.");
		checkArgument(isNotEmpty(providerId), "providerId must be provided.");

		this.username = username;
		this.provider = provider;
		this.providerId = providerId;
		this.profileImage = profileImage;
		this.group = group;
	}

	public Optional<String> getProfileImage() {
		return Optional.ofNullable(profileImage);
	}
}
