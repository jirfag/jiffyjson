#pragma once

#define jvector_def(name_, type_) struct jvec_ ## name_ { \
    type_ *items_; \
    uint32_t count_; \
    uint32_t capacity_; \
}

#define jvector(name_) struct jvec_ ## name_

#define jvector_static_initializer() { \
    .items_ = NULL, \
    .count_ = 0, \
    .capacity_ = 0 \
}

#define jvector_push_back(vec_) ({ \
    if ((vec_)->capacity_ == (vec_)->count_) \
        jvector_ensure(vec_, (vec_)->capacity_ + 1); \
    assert((vec_)->items_); \
    __typeof__((vec_)->items_[0]) *ret_ = &(vec_)->items_[(vec_)->count_]; \
    (vec_)->count_++; \
    ret_; \
})

#define jvector_delete(vec_) ({ \
    free((vec_)->items_); \
})

#define jvector_size(vec_) (vec_)->count_

#define jvector_get_val(vec_, i_) ((__typeof__((vec_)->items_[0]) *)(vec_)->items_)[i]

#define jvector_ensure(vec_, n_) ({ \
    if ((vec_)->count_ + n_ > (vec_)->capacity_) { \
        (vec_)->capacity_ = (vec_)->capacity_ + n_; \
        (vec_)->items_ = (__typeof__((vec_)->items_[0]) *)realloc((vec_)->items_, (vec_)->capacity_ * sizeof((vec_)->items_[0])); \
    } \
})

#define jvector_reset(vec_) ({ \
    (vec_)->count_ = 0; \
})

#define jvector_data(vec_) (vec_)->items_
