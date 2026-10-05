import { RenderPlugin } from '@11ty/eleventy';

export default function (eleventyConfig) {
  eleventyConfig.addPlugin(RenderPlugin);
  eleventyConfig.addPassthroughCopy({ 'src/assets': 'assets' });
  eleventyConfig.amendLibrary('md', (md) => {
    const original = md.renderer.rules.heading_open;
    md.renderer.rules.heading_open = (tokens, index, options, env, self) => {
      const text = tokens[index + 1].content;
      const id = text.toLowerCase().replace(/[^a-z0-9\s-]/g, '').trim().replace(/\s+/g, '-');
      tokens[index].attrSet('id', id);
      return original ? original(tokens, index, options, env, self) : self.renderToken(tokens, index, options);
    };
  });
  return {
    dir: { input: 'src', output: 'dist', includes: '_includes', data: '_data' },
    templateFormats: ['md', 'njk'],
    markdownTemplateEngine: false,
    htmlTemplateEngine: 'njk'
  };
}
