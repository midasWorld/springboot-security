package com.prgrms.devcourse.user;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "group_permission")
@Entity
public class GroupPermission {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	@ManyToOne
	@JoinColumn(name = "group_id", unique = true)
	Group group;

	@ManyToOne
	@JoinColumn(name = "permission_id", unique = true)
	Permission permission;

	@Builder
	public GroupPermission(Group group, Permission permission) {
		this.group = group;
		this.permission = permission;
	}
}
