// PAEWS (Luo et al., IEEE TIFS 2025) Type-3 cryptanalysis benchmark.
// Real group/pairing implementation: herumi/mcl with BLS12-381.
// Educational, reproducible evaluation only. NOT production crypto.
//
// Paper Section V:
//   C1=g1^r, C2=h^r, D_i=g1^(t^ck_i/gamma) * h_i^(r/gamma)
//   T0=e(g1,g2)^rp
//   T1=g2^(rp * sum_i alpha_i*t^(-tk_i))
//   T2=g2^(rp * sum_i beta_i*t^(-tk_i))
//   E_i=g2^(rp*gamma*t^(-tk_i))
//   Test: prod_i e(D_i,E_i) / (e(C1,T1)e(C2,T2)) == T0^ell
//
// Vulnerability: Shift_delta(TD) =
//   (T0,T1^(t^-delta),T2^(t^-delta), E_i^(t^-delta))
// equals a legitimate TD for tk_i+delta without either secret key.

#include <mcl/bls12_381.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace bn = mcl::bn;
using Fr = bn::Fr;
using G1 = bn::G1;
using G2 = bn::G2;
using GT = bn::GT;

namespace {
volatile std::uint64_t g_sink = 0;
using Clock = std::chrono::steady_clock;

void require(bool ok, const std::string& msg)
{
    if (!ok) throw std::runtime_error(msg);
}

Fr random_fr(bool nonzero = false)
{
    Fr x;
    do { x.setByCSPRNG(); } while (nonzero && x.isZero());
    return x;
}

// Integer exponentiation in the *scalar field*. Negative exponent means inverse.
// This is not elliptic-curve exponentiation.
Fr scalar_pow_signed(const Fr& base, std::int64_t e)
{
    require(e != INT64_MIN, "unsupported exponent");
    bool negative = (e < 0);
    std::uint64_t k = static_cast<std::uint64_t>(negative ? -e : e);
    Fr b = base;
    Fr result(1);
    while (k) {
        if (k & 1U) Fr::mul(result, result, b);
        k >>= 1U;
        if (k) Fr::mul(b, b, b);
    }
    if (negative) Fr::inv(result, result);
    return result;
}

GT pair(const G1& p, const G2& q)
{
    GT x;
    bn::pairing(x, p, q);
    return x;
}

G1 scale_g1(const G1& p, const Fr& a)
{
    G1 x;
    G1::mul(x, p, a);
    return x;
}

G2 scale_g2(const G2& p, const Fr& a)
{
    G2 x;
    G2::mul(x, p, a);
    return x;
}

GT pow_gt(const GT& p, const Fr& a)
{
    GT x;
    GT::pow(x, p, a);
    return x;
}

struct Params {
    G1 g1;
    G2 g2;
    GT pairing_base;
    Fr t;
};
struct Sender {
    Fr gamma;
    G2 pk;
};
struct Receiver {
    Fr s;
    std::vector<Fr> alpha;
    std::vector<Fr> beta;
    G1 h;
    std::vector<G1> h_i;
};
struct Ciphertext {
    G1 C1;
    G1 C2;
    std::vector<G1> D;
};
struct Token {
    GT T0;
    G2 T1;
    G2 T2;
    std::vector<G2> E;
};

Params setup()
{
    // initPairing() is called once in main before setup().
    Params pp;
    const std::string label1 = "PAEWS-2025-TEST-G1";
    const std::string label2 = "PAEWS-2025-TEST-G2";
    bn::hashAndMapToG1(pp.g1, label1.data(), label1.size());
    bn::hashAndMapToG2(pp.g2, label2.data(), label2.size());
    pp.pairing_base = pair(pp.g1, pp.g2);
    // The original Setup samples t from Fr^*.  t=1 is allowed but makes
    // keyword encoding degenerate.  Exclude it in this benchmark so the
    // expected b=1 negative cases are well-defined; Pr[t=1]=1/(q-1).
    do { pp.t = random_fr(true); } while (pp.t == Fr(1));
    return pp;
}

Sender keygen_sender(const Params& pp)
{
    Sender s;
    s.gamma = random_fr(true);
    s.pk = scale_g2(pp.g2, s.gamma);
    return s;
}

Receiver keygen_receiver(const Params& pp, std::size_t n)
{
    Receiver sk;
    sk.s = random_fr();
    sk.alpha.resize(n);
    sk.beta.resize(n);
    sk.h_i.resize(n);
    sk.h = scale_g1(pp.g1, sk.s);
    for (std::size_t i = 0; i < n; i++) {
        sk.alpha[i] = random_fr();
        sk.beta[i] = random_fr();
        G1 a = scale_g1(pp.g1, sk.alpha[i]);
        G1 b = scale_g1(sk.h, sk.beta[i]);
        G1::add(sk.h_i[i], a, b);
    }
    return sk;
}

Ciphertext encrypt(const Params& pp, const Sender& skS,
                   const Receiver& pkR, const std::vector<int>& ck)
{
    require(ck.size() == pkR.h_i.size(), "bad plaintext length");
    Ciphertext ct;
    const Fr r = random_fr();
    Fr inv_gamma;
    Fr::inv(inv_gamma, skS.gamma);
    ct.C1 = scale_g1(pp.g1, r);
    ct.C2 = scale_g1(pkR.h, r);
    ct.D.resize(ck.size());
    const Fr r_over_gamma = r * inv_gamma;
    for (std::size_t i = 0; i < ck.size(); i++) {
        require(ck[i] >= 0, "ciphertext keyword cannot contain wildcards");
        const Fr t_to_ck = scalar_pow_signed(pp.t, ck[i]);
        const Fr enc_exp = t_to_ck * inv_gamma;
        G1 a = scale_g1(pp.g1, enc_exp);
        G1 b = scale_g1(pkR.h_i[i], r_over_gamma);
        G1::add(ct.D[i], a, b);
    }
    return ct;
}

// tk is the non-wildcard prefix; remaining positions are '*' (Section V).
// The randomness rp (r' in [1], rho in the comment paper) is given explicitly
// so that Lemma 1 can be checked with the same rho on both sides.
Token trapdoor_with(const Params& pp, const Sender& pkS,
                    const Receiver& skR, const std::vector<int>& tk, const Fr& rp)
{
    require(!tk.empty() && tk.size() <= skR.alpha.size(), "bad token prefix length");
    Fr alpha_sum(0), beta_sum(0);
    Token td;
    td.E.resize(tk.size());
    for (std::size_t i = 0; i < tk.size(); i++) {
        require(tk[i] >= 0, "specified token characters must be nonnegative");
        const Fr weight = scalar_pow_signed(pp.t, -static_cast<std::int64_t>(tk[i]));
        alpha_sum += skR.alpha[i] * weight;
        beta_sum += skR.beta[i] * weight;
        td.E[i] = scale_g2(pp.g2, rp * pkS.gamma * weight);
    }
    td.T0 = pow_gt(pp.pairing_base, rp);
    td.T1 = scale_g2(pp.g2, rp * alpha_sum);
    td.T2 = scale_g2(pp.g2, rp * beta_sum);
    return td;
}

// Trapdoor algorithm of [1], Section V: fresh rp <- Z_q.
Token trapdoor(const Params& pp, const Sender& pkS,
               const Receiver& skR, const std::vector<int>& tk)
{
    return trapdoor_with(pp, pkS, skR, tk, random_fr());
}

// PEWS ([1], Section IV) has D_i = g1^{t^{x_i}} h_i^r and E_i = g2^{rho t^{-y_i}},
// with T0, T1, T2, Test, and the receiver keys (t public) as in PAEWS.  These are
// exactly the PAEWS algorithms above with gamma = 1, so PEWS is run through them.
Sender pews_gamma_one(const Params& pp)
{
    Sender s;
    s.gamma = Fr(1);
    s.pk = pp.g2;
    return s;
}

bool test(const Ciphertext& ct, const Token& td)
{
    require(!td.E.empty() && td.E.size() <= ct.D.size(), "bad token length");
    GT numerator;  // product of pairings e(D_i,E_i)
    bool first = true;
    for (std::size_t i = 0; i < td.E.size(); i++) {
        const GT current = pair(ct.D[i], td.E[i]);
        if (first) { numerator = current; first = false; }
        else { GT::mul(numerator, numerator, current); }
    }
    GT denominator = pair(ct.C1, td.T1);
    const GT second = pair(ct.C2, td.T2);
    GT::mul(denominator, denominator, second);
    GT quotient;
    GT::div(quotient, numerator, denominator);
    const GT expected = pow_gt(td.T0, Fr(static_cast<int>(td.E.size())));
    return quotient == expected;
}

// Public transformation, no skS, skR or pairing evaluation.
Token shift_token(const Params& pp, const Token& td, std::int64_t delta)
{
    const Fr u = scalar_pow_signed(pp.t, -delta);
    Token out;
    out.T0 = td.T0;
    out.T1 = scale_g2(td.T1, u);
    out.T2 = scale_g2(td.T2, u);
    out.E.resize(td.E.size());
    for (std::size_t i = 0; i < td.E.size(); i++) {
        out.E[i] = scale_g2(td.E[i], u);
    }
    return out;
}

Token universal_token(const Params& pp)
{
    Token td;
    const Fr zero(0);
    td.T0 = pow_gt(pp.pairing_base, zero);
    td.T1 = scale_g2(pp.g2, zero);
    td.T2 = scale_g2(pp.g2, zero);
    td.E.emplace_back(scale_g2(pp.g2, zero));
    return td;
}

bool same_token(const Token& a, const Token& b)
{
    if (a.E.size() != b.E.size()) return false;
    if (!(a.T0 == b.T0) || !(a.T1 == b.T1) || !(a.T2 == b.T2)) return false;
    for (std::size_t i = 0; i < a.E.size(); i++) {
        if (!(a.E[i] == b.E[i])) return false;
    }
    return true;
}

// Lemma 1 in general form: random ell in [1,n], characters y_i in [0,100],
// non-wrapping delta in [-min y_i, 100], and rho != 0.  Checks
// Shift_delta(Trapdoor(y; rho)) == Trapdoor(y + delta; rho) component-wise, and,
// as a negative control, that it differs from the trapdoor of another keyword.
bool check_lemma1(const Params& pp, const Sender& s, const Receiver& r,
                  std::size_t n, std::mt19937_64& rng)
{
    std::uniform_int_distribution<std::size_t> length(1, n);
    std::uniform_int_distribution<int> character(0, 100);
    std::vector<int> y(length(rng));
    for (int& c : y) c = character(rng);
    const int y_min = *std::min_element(y.begin(), y.end());
    std::uniform_int_distribution<int> shift(-y_min, 100);
    const int delta = shift(rng);
    std::vector<int> y_shifted(y);
    for (int& c : y_shifted) c += delta;
    std::vector<int> y_other(y_shifted);
    y_other[0] += 1;
    const Fr rho = random_fr(true);
    const Token shifted = shift_token(pp, trapdoor_with(pp, s, r, y, rho), delta);
    return same_token(shifted, trapdoor_with(pp, s, r, y_shifted, rho))
        && !same_token(shifted, trapdoor_with(pp, s, r, y_other, rho));
}

std::vector<int> keyword(std::size_t n, int first, int second = 0)
{
    std::vector<int> w(n, 0);
    w[0] = first;
    w[1] = second;
    return w;
}

struct Sample {
    Ciphertext ct0, ct1, ct2;
    Token td0, td1, td2;
    Token td00, td01;
};

Sample make_sample(const Params& pp, const Sender& s,
                   const Receiver& r, std::size_t n)
{
    Sample x;
    x.ct0 = encrypt(pp, s, r, keyword(n, 0));
    x.ct1 = encrypt(pp, s, r, keyword(n, 1));
    x.ct2 = encrypt(pp, s, r, keyword(n, 2));
    x.td0 = trapdoor(pp, s, r, {0});
    x.td1 = trapdoor(pp, s, r, {1});
    x.td2 = trapdoor(pp, s, r, {2});
    x.td00 = trapdoor(pp, s, r, {0, 0});
    x.td01 = trapdoor(pp, s, r, {0, 1});
    return x;
}

struct Validation {
    std::size_t count = 0;
    std::size_t honest = 0;
    std::size_t ci = 0;
    std::size_t ti = 0;
    std::size_t ti_public = 0;
    std::size_t universal = 0;
    std::size_t lemma1 = 0;
    std::size_t pews_honest = 0;
    std::size_t pews_ci = 0;
    std::size_t nondegenerate_failures = 0;
};

// Each trial is an independent experiment: fresh t, sender key, receiver key,
// and Enc/Trapdoor randomness.  Only the hash-derived generators are fixed.
Validation validate(std::size_t n, std::size_t trials)
{
    Validation v;
    std::mt19937_64 rng(std::random_device{}());  // test-case choice only, not key material
    for (std::size_t i = 0; i < trials; i++) {
        const Params pp = setup();
        const Sender s = keygen_sender(pp);
        const Receiver r = keygen_receiver(pp, n);
        const Sample x = make_sample(pp, s, r, n);
        const bool honest = test(x.ct0, x.td0) && test(x.ct1, x.td1)
                         && test(x.ct2, x.td2) && !test(x.ct1, x.td0);
        // CI: legal TD(2) query (rejects ck0 and ck1) -> Shift(-2) -> TD(0).
        const Token ci_td = shift_token(pp, x.td2, -2);
        const bool ci = test(x.ct0, ci_td) && !test(x.ct1, ci_td);
        // TI: legal Enc(ck=2) query (rejects tk0 and tk1).
        const Token ti0_td = shift_token(pp, x.td0, +2);
        const Token ti1_td = shift_token(pp, x.td1, +2);
        const bool ti = test(x.ct2, ti0_td) && !test(x.ct2, ti1_td);
        // No query: search patterns (0,0,*,...) and (0,1,*,...).
        const bool ti_public = (x.td00.E[0] == x.td00.E[1])
                            && (x.td01.E[0] != x.td01.E[1]);
        const Token all = universal_token(pp);
        const bool universal = test(x.ct0, all) && test(x.ct1, all) && test(x.ct2, all);
        const bool lemma1 = check_lemma1(pp, s, r, n, rng);
        // PEWS: honest Test, then the same CI attack (legal TD(2) -> Shift(-2) -> TD(0)).
        const Sender pews = pews_gamma_one(pp);
        const Ciphertext pews_ct0 = encrypt(pp, pews, r, keyword(n, 0));
        const Ciphertext pews_ct1 = encrypt(pp, pews, r, keyword(n, 1));
        const Token pews_td0 = trapdoor(pp, pews, r, {0});
        const bool pews_honest = test(pews_ct0, pews_td0) && !test(pews_ct1, pews_td0);
        const Token pews_ci_td = shift_token(pp, trapdoor(pp, pews, r, {2}), -2);
        const bool pews_ci = test(pews_ct0, pews_ci_td) && !test(pews_ct1, pews_ci_td);
        v.count++;
        v.lemma1 += lemma1 ? 1 : 0;
        v.pews_honest += pews_honest ? 1 : 0;
        v.pews_ci += pews_ci ? 1 : 0;
        v.honest += honest ? 1 : 0;
        v.ci += ci ? 1 : 0;
        v.ti += ti ? 1 : 0;
        v.ti_public += ti_public ? 1 : 0;
        v.universal += universal ? 1 : 0;
        if (!honest || !ci || !ti || !ti_public || !universal
            || !lemma1 || !pews_honest || !pews_ci) {
            v.nondegenerate_failures++;
        }
    }
    return v;
}

struct Stats {
    std::string name;
    std::size_t count;
    std::size_t batch;
    double mean_us, median_us, stdev_us, p95_us, min_us, max_us;
};

using Operation = std::function<void(std::size_t)>;

Stats benchmark(const std::string& name, std::size_t runs,
                std::size_t warmup, std::size_t batch,
                const Operation& operation)
{
    for (std::size_t i = 0; i < warmup * batch; i++) operation(i);
    std::vector<double> values;
    values.reserve(runs);
    for (std::size_t i = 0; i < runs; i++) {
        const auto start = Clock::now();
        for (std::size_t j = 0; j < batch; j++) operation(i * batch + j);
        const auto end = Clock::now();
        const double us = std::chrono::duration<double, std::micro>(end-start).count();
        values.push_back(us/static_cast<double>(batch));
    }
    const double mean = std::accumulate(values.begin(), values.end(), 0.0)
                      / static_cast<double>(values.size());
    double variance = 0;
    for (const double x : values) variance += (x-mean)*(x-mean);
    variance /= static_cast<double>(values.size());
    std::sort(values.begin(), values.end());
    const std::size_t p95_index = std::min<std::size_t>(runs - 1, (runs * 95 + 99)/100 - 1);
    return {name, runs, batch, mean, values[runs/2], std::sqrt(variance),
            values[p95_index], values.front(), values.back()};
}

struct Options {
    std::size_t n = 8;
    std::size_t runs = 10000;
    std::size_t warmup = 50;
    std::size_t validate_trials = 128;
    std::size_t pool = 16;
    std::string csv;
};

void usage(const char* executable)
{
    std::cout << "Usage: " << executable
              << " [--n 8] [--runs 10000] [--warmup 50]"
              << " [--validate 128] [--pool 16] [--csv results.csv]\n";
}

Options parse_options(int argc, char** argv)
{
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") { usage(argv[0]); std::exit(0); }
        require(i+1 < argc, "missing value for " + arg);
        const std::string v = argv[++i];
        if (arg == "--n") o.n = std::stoull(v);
        else if (arg == "--runs") o.runs = std::stoull(v);
        else if (arg == "--warmup") o.warmup = std::stoull(v);
        else if (arg == "--validate") o.validate_trials = std::stoull(v);
        else if (arg == "--pool") o.pool = std::stoull(v);
        else if (arg == "--csv") o.csv = v;
        else throw std::runtime_error("unknown option: " + arg);
    }
    require(o.n >= 2 && o.n <= 512, "--n must be in [2,512]");
    require(o.runs <= 1000000, "invalid --runs (0 = validation only)");
    require(o.pool >= 1 && o.pool <= 4096, "invalid --pool");
    return o;
}

void print_and_save(const std::vector<Stats>& stats, const Options& o)
{
    std::cout << "\n=== Average cost over " << o.runs << " timed samples per operation ===\n";
    std::cout << std::left << std::setw(30) << "Operation"
              << std::right << std::setw(14) << "mean (us)"
              << std::setw(14) << "median (us)"
              << std::setw(14) << "p95 (us)"
              << std::setw(14) << "stddev (us)"
              << "\n";
    std::cout << std::fixed << std::setprecision(3);
    for (const auto& s : stats) {
        std::cout << std::left << std::setw(30) << s.name
                  << std::right << std::setw(14) << s.mean_us
                  << std::setw(14) << s.median_us
                  << std::setw(14) << s.p95_us
                  << std::setw(14) << s.stdev_us << "\n";
    }
    if (!o.csv.empty()) {
        std::ofstream out(o.csv);
        require(out.good(), "cannot open CSV file: " + o.csv);
        out << "operation,runs,batch,mean_us,median_us,p95_us,stddev_us,min_us,max_us\n";
        out << std::fixed << std::setprecision(6);
        for (const auto& s : stats) {
            out << s.name << ',' << s.count << ',' << s.batch << ','
                << s.mean_us << ',' << s.median_us << ',' << s.p95_us << ','
                << s.stdev_us << ',' << s.min_us << ',' << s.max_us << '\n';
        }
        std::cout << "Saved CSV: " << o.csv << "\n";
    }
}
} // namespace

int main(int argc, char** argv)
try {
    const Options o = parse_options(argc, argv);
    const auto init_start = Clock::now();
    bn::initPairing(mcl::BLS12_381);
    const Params pp = setup();
    const Sender sender = keygen_sender(pp);
    const Receiver receiver = keygen_receiver(pp, o.n);
    const auto init_end = Clock::now();

    std::cout << "PAEWS cryptanalysis benchmark / herumi mcl / BLS12-381 (Type-3)\n";
    std::cout << "n=" << o.n << "  runs=" << o.runs
              << "  warmup=" << o.warmup << "  validation=" << o.validate_trials
              << "  pool=" << o.pool << "\n";
    std::cout << "mcl init + Setup + initial sender/receiver KeyGen: "
              << std::chrono::duration<double, std::milli>(init_end-init_start).count()
              << " ms (one-time; not in attack timings)\n";
    std::cout << "Hardware concurrency: " << std::thread::hardware_concurrency() << "\n";
    std::cout << "Important: t=1 excluded (negligible-probability degeneration);"
              << " r'=0 not excluded by the algorithm.\n";

    const Validation v = validate(o.n, o.validate_trials);
    std::cout << "\n=== Independent fresh-randomness validation ===\n"
              << "Honest Test and negative control: " << v.honest << '/' << v.count << "\n"
              << "CI attack (1 legal TD query):    " << v.ci << '/' << v.count << "\n"
              << "TI attack (1 legal Enc query):   " << v.ti << '/' << v.count << "\n"
              << "TI public equality (0 queries): " << v.ti_public << '/' << v.count << "\n"
              << "Universal token (all matches): " << v.universal << '/' << v.count << "\n"
              << "Lemma 1 (random ell, y, delta, rho): " << v.lemma1 << '/' << v.count << "\n"
              << "PEWS honest Test and negative control: " << v.pews_honest << '/' << v.count << "\n"
              << "PEWS CI attack (1 legal TD query): " << v.pews_ci << '/' << v.count << "\n";
    require(v.honest == v.count && v.ci == v.count && v.ti == v.count
            && v.ti_public == v.count && v.universal == v.count
            && v.lemma1 == v.count && v.pews_honest == v.count && v.pews_ci == v.count,
            "validation failed (check t, r' degeneracy or implementation)");
    if (o.runs == 0) {
        std::cout << "\nTiming skipped (--runs 0).\n";
        return 0;
    }

    std::vector<Sample> pool;
    pool.reserve(o.pool);
    for (std::size_t i = 0; i < o.pool; ++i) pool.emplace_back(make_sample(pp, sender, receiver, o.n));
    std::vector<Stats> stats;
    const auto src = [&](std::size_t i) -> const Sample& { return pool[i % pool.size()]; };
    const auto record = [&](const std::string& name, std::size_t batch,
                            const Operation& f) {
        std::cout << "measuring " << name << " ..." << std::endl;
        stats.push_back(benchmark(name, o.runs, o.warmup, batch, f));
    };

    record("Enc (n characters)", 1, [&](std::size_t i) {
        const Ciphertext ct = encrypt(pp, sender, receiver, keyword(o.n, static_cast<int>(i%3)));
        g_sink += static_cast<std::uint64_t>(ct.D.size());
    });
    record("Trapdoor (ell=1)", 1, [&](std::size_t i) {
        const Token td = trapdoor(pp, sender, receiver, {static_cast<int>(i%3)});
        g_sink += static_cast<std::uint64_t>(td.E.size());
    });
    record("Test (ell=1; 3 pairings)", 1, [&](std::size_t i) {
        const auto& x = src(i);
        g_sink += test(x.ct0, x.td0) ? 1U : 0U;
    });
    record("Shift only (3 G2 mul)", 1, [&](std::size_t i) {
        const Token shifted = shift_token(pp, src(i).td2, -2);
        g_sink += static_cast<std::uint64_t>(shifted.E.size());
    });
    record("CI: Shift+Test", 1, [&](std::size_t i) {
        const auto& x = src(i);
        const Token shifted = shift_token(pp, x.td2, -2);
        const bool b = (i & 1U) != 0U;
        const bool decision0 = test(b ? x.ct1 : x.ct0, shifted);
        g_sink += (decision0 != b) ? 1U : 0U;
    });
    record("CI: oracle TD+Shift+Test", 1, [&](std::size_t i) {
        const auto& x = src(i);
        const Token oracle_td = trapdoor(pp, sender, receiver, {2});
        const Token shifted = shift_token(pp, oracle_td, -2);
        const bool b = (i & 1U) != 0U;
        const bool decision0 = test(b ? x.ct1 : x.ct0, shifted);
        g_sink += (decision0 != b) ? 1U : 0U;
    });
    record("TI: Shift+Test", 1, [&](std::size_t i) {
        const auto& x = src(i);
        const bool b = (i & 1U) != 0U;
        const Token shifted = shift_token(pp, b ? x.td1 : x.td0, +2);
        const bool decision0 = test(x.ct2, shifted);
        g_sink += (decision0 != b) ? 1U : 0U;
    });
    record("TI: oracle Enc+Shift+Test", 1, [&](std::size_t i) {
        const auto& x = src(i);
        const Ciphertext oracle_ct = encrypt(pp, sender, receiver, keyword(o.n, 2));
        const bool b = (i & 1U) != 0U;
        const Token shifted = shift_token(pp, b ? x.td1 : x.td0, +2);
        const bool decision0 = test(oracle_ct, shifted);
        g_sink += (decision0 != b) ? 1U : 0U;
    });
    // Time 256 public equality comparisons per sample to limit timer noise.
    // No pairing, no oracle, no G2 exponentiation.
    record("TI public: E1==E2", 256, [&](std::size_t i) {
        const auto& x = src(i);
        const bool b = (i & 1U) != 0U;
        const Token& td = b ? x.td01 : x.td00;
        const bool decision0 = (td.E[0] == td.E[1]);
        g_sink += (decision0 != b) ? 1U : 0U;
    });

    print_and_save(stats, o);
    std::cout << "\nAll tests completed; optimizer sink=" << g_sink << "\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << '\n';
    return 1;
}
