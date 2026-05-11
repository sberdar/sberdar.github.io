module.exports = function(eleventyConfig) {
  eleventyConfig.addPassthroughCopy("assets");
  eleventyConfig.addPassthroughCopy("CNAME");
  
  eleventyConfig.addFilter("readingTime", function(content) {
    const wordsPerMinute = 200;
    const words = content.trim().split(/\s+/).length;
    const minutes = Math.ceil(words / wordsPerMinute);
    return `${minutes} min read`;
  });
  return {
    dir: {
      input: ".",
      includes: "_includes",
      output: "_site"
    }
  };
};