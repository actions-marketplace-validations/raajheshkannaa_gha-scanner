import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

/**
 * supply-chain/unpinned-container-images
 *
 * Detects job `container:` and `services.<id>.image` references that are
 * not pinned to an immutable digest (`@sha256:...`). Container tags
 * (including the implicit `latest`) are mutable pointers: a registry push
 * can swap the code your job runs without any change to your workflow.
 * This is the container analogue of pinning actions by SHA.
 *
 * Complements supply-chain/docker-mutable-tags, which only covers
 * `docker://` action references, not job/service containers.
 */

const DIGEST_RE = /@sha256:[0-9a-f]{64}/i;
const EXPRESSION_RE = /\$\{\{/;

interface ImageRef {
  image: string;
  where: string;
}

function extractImageString(container: unknown): string | null {
  if (typeof container === 'string') return container;
  if (container && typeof container === 'object' && !Array.isArray(container)) {
    const image = (container as Record<string, unknown>)['image'];
    if (typeof image === 'string') return image;
  }
  return null;
}

function collectImages(parsed: Record<string, unknown>): ImageRef[] {
  const out: ImageRef[] = [];
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return out;

  for (const [jobId, jobDef] of Object.entries(jobs as Record<string, unknown>)) {
    if (!jobDef || typeof jobDef !== 'object') continue;
    const job = jobDef as Record<string, unknown>;

    const containerImage = extractImageString(job['container']);
    if (containerImage) out.push({ image: containerImage, where: `job "${jobId}" container` });

    const services = job['services'];
    if (services && typeof services === 'object' && !Array.isArray(services)) {
      for (const [svcId, svcDef] of Object.entries(services as Record<string, unknown>)) {
        const svcImage = extractImageString(svcDef);
        if (svcImage) out.push({ image: svcImage, where: `job "${jobId}" service "${svcId}"` });
      }
    }
  }
  return out;
}

/** Returns the tag if the image is unpinned, or null if pinned by digest / not analyzable. */
function classifyImage(image: string): { unpinned: boolean; implicitLatest: boolean; tag: string } | null {
  const trimmed = image.trim();
  if (!trimmed) return null;
  if (EXPRESSION_RE.test(trimmed)) return null; // dynamic, cannot evaluate
  if (DIGEST_RE.test(trimmed)) return null; // pinned by digest

  // Strip an optional registry host (which may contain a port colon) before
  // looking for the tag separator, so `ghcr.io:443/x` does not confuse us.
  const lastSlash = trimmed.lastIndexOf('/');
  const namePart = lastSlash === -1 ? trimmed : trimmed.slice(lastSlash + 1);
  const colon = namePart.lastIndexOf(':');

  if (colon === -1) {
    return { unpinned: true, implicitLatest: true, tag: 'latest (implicit)' };
  }
  const tag = namePart.slice(colon + 1);
  return { unpinned: true, implicitLatest: tag === 'latest', tag };
}

export const unpinnedContainerImagesCheck: CheckDefinition = {
  id: 'supply-chain/unpinned-container-images',
  name: 'Unpinned container images',
  description:
    'Detects job container and service images referenced by mutable tag instead of an immutable @sha256 digest.',
  category: 'supply-chain',
  severity: 'medium',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      for (const ref of collectImages(workflow.parsed)) {
        const cls = classifyImage(ref.image);
        if (!cls || !cls.unpinned) continue;

        const severity = cls.implicitLatest ? ('high' as const) : ('medium' as const);
        const tagNote = cls.implicitLatest
          ? 'no tag at all, so it resolves to the mutable `latest` tag'
          : `the mutable tag \`${cls.tag}\``;

        findings.push({
          checkId: 'supply-chain/unpinned-container-images',
          severity,
          category: 'supply-chain',
          title: `Unpinned container image in ${ref.where}: ${ref.image}`,
          description:
            `Workflow "${workflow.name}" runs ${ref.where} on \`${ref.image}\`, which uses ${tagNote}. ` +
            'Container tags are mutable: the registry can repoint a tag at different image contents at any time.',
          risk:
            'A mutable container tag is a supply chain hole equivalent to an unpinned action. ' +
            'A compromised registry account, a routine rebuild, or a malicious push can change the code your job executes without any change to the workflow file. ' +
            'CI containers run with access to your checkout, secrets, and the GITHUB_TOKEN.',
          remediation:
            'Pin the image to its digest:\n\n' +
            '```yaml\n' +
            'jobs:\n' +
            '  build:\n' +
            '    container:\n' +
            `      image: ${ref.image.split(':')[0]}@sha256:<digest>\n` +
            '```\n\n' +
            'Resolve the digest with `docker buildx imagetools inspect <image>:<tag>` or `docker inspect --format=\'{{index .RepoDigests 0}}\' <image>:<tag>`. ' +
            'Keep a renovate/dependabot rule to bump digests as new versions ship.',
          file: workflow.path,
          line: findLineNumber(workflow.content, ref.image),
          evidence: `${ref.where}: image ${ref.image}`,
        });
      }
    }

    return findings;
  },
};
