package mw.course.security.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor //for builder
@Entity //from jakarta
@Table(name = "_user", uniqueConstraints = {
        @UniqueConstraint(columnNames = "email")}) //because User is reserved
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;
    private String firstname;
    private String lastname;
    @Column(name = "email", unique = true, nullable = false)
    private String email;
    private String pass; //or password without overriding the get method
    @Enumerated(EnumType.STRING) //because role is enum
    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority((role.name()))); //just one role
    }

    @Override
    public String getPassword() {
        return pass;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; //changed to true, because it is NON expired !!
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; //changed to true
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; //changed to true
    }

    @Override
    public boolean isEnabled() {
        return true; //changed to true
    }
}
