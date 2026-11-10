// cov_runner.cc - replays fuzzer inputs through a harness for coverage builds.
//
// Upstream's standalone_fuzz_target_runner.cpp never calls
// LLVMFuzzerInitialize, so server_fuzzer would run with no routes registered
// and coverage of handler dispatch would be undercounted. This runner calls it
// (if the harness defines it) and accepts both files and directories, so an
// AFL++ queue/ directory can be passed directly.

#include <cstdint>
#include <cstdio>
#include <dirent.h>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" __attribute__((weak)) int LLVMFuzzerInitialize(int *argc,
                                                          char ***argv);

static size_t g_count = 0;

static void run_file(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return;
  std::vector<char> bytes((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
  // Exact-size heap buffer, so any overread is visible to sanitizers.
  std::vector<uint8_t> buf(bytes.begin(), bytes.end());
  LLVMFuzzerTestOneInput(buf.data(), buf.size());
  ++g_count;
}

static void run_path(const std::string &path) {
  struct stat st {};
  if (stat(path.c_str(), &st) != 0) return;
  if (S_ISDIR(st.st_mode)) {
    DIR *d = opendir(path.c_str());
    if (!d) return;
    while (dirent *e = readdir(d)) {
      std::string name = e->d_name;
      if (name == "." || name == "..") continue;
      // Skip AFL++ bookkeeping files such as .state
      if (name[0] == '.') continue;
      run_path(path + "/" + name);
    }
    closedir(d);
  } else if (S_ISREG(st.st_mode)) {
    run_file(path);
  }
}

int main(int argc, char **argv) {
  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
  for (int i = 1; i < argc; i++) run_path(argv[i]);
  std::fprintf(stderr, "cov_runner: executed %zu inputs\n", g_count);
  return 0;
}
