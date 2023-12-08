package com.example.Basic.Demo.Entity.entity;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Date;


/**
 * @author Ismail Dudekula
 * @version 1.0
 * @since 24-03-2022
 */

@Setter
@Getter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity implements Serializable {
 //   private static final long serialVersionUID = -5101214195716534496L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @CreatedBy
    private Long createdBy;

    @JsonIgnore
    @LastModifiedBy
    private Long updatedBy;

    @Column(updatable = false)
    @JsonIgnore
    @CreationTimestamp
    private Timestamp createdOn = new Timestamp( new Date().getTime() );

    @UpdateTimestamp
    @JsonIgnore
    private Timestamp updatedOn = new Timestamp( new Date().getTime() );

    private Boolean isDeleted = Boolean.FALSE;

    private Boolean isActive = Boolean.TRUE;

    @Column(columnDefinition = "text")
    private String searchKey;
}
