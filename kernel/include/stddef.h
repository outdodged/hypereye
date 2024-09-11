#pragma once

#include <linux/types.h>
#include <linux/kvm_types.h>

#define DBG	KERN_INFO "[HYPEREYE]: "

#define TEST_PTR(a, b, c, d) if (a == (b) NULL) { c; return d; }

#define SUCCESS     0
#define ERROR       -1

/*
typedef uint64_t        gva_t;
typedef uint64_t        gpa_t;
typedef uint64_t        hva_t;
typedef uint64_t        hpa_t;*/