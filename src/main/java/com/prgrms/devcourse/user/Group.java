package com.prgrms.devcourse.user;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@ToString
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "groups")
@Entity
public class Group {

	@Id @GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	private String name;

	public Group(String name) {
		this.name = name;
	}

	@OneToMany(mappedBy = "group")
	List<GroupPermission> permissions = new ArrayList<>();

	public List<GrantedAuthority> getAuthorities() {
		return permissions.stream()
			.map(gp -> new SimpleGrantedAuthority(gp.getPermission().getName()))
			.collect(Collectors.toList());
	}
}
