#define ijvector_def(name_, type_) struct ijvec_ ## name_ { \
    uint32_t count_; \
    type_ size_[0]; \
    type_ items_[]; \
}

#define ijvector(name_) struct ijvec_ ## name_

#define ijvector_init(name_, data_, n_) ({ \
    ijvector(name_) *vec_; \
    size_t elems_space_ = sizeof(vec_->size_[0]) * n_; \
    vec_ = malloc(sizeof(*vec_) + elems_space_); \
    memcpy(vec_->items_, data_, elems_space_); \
    vec_->count_ = n_; \
    vec_; \
})

#define ijvector_size(vec_) vec_->count_
