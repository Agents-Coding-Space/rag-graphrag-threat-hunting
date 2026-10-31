import React, { useEffect, useRef } from 'react';
import cytoscape, { Core } from 'cytoscape';
import { CytoscapeElement } from '../types';
import { ZoomInIcon, ZoomOutIcon, MaximizeIcon } from './SvgIcons';

interface Props {
  elements: CytoscapeElement[];
  onSelectNode: (nodeData: any) => void;
  selectedNodeId?: string;
  theme?: 'dark' | 'light';
}

export const CytoscapeGraph: React.FC<Props> = ({ elements, onSelectNode, selectedNodeId, theme = 'dark' }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const isLight = theme === 'light';
  const nodeTextColor = isLight ? '#111827' : '#F3F4F6';
  const nodeTextBg = isLight ? 'rgba(255, 255, 255, 0.9)' : 'rgba(17, 24, 39, 0.85)';
  const edgeColor = isLight ? '#9CA3AF' : '#374151';
  const edgeArrowColor = isLight ? '#6B7280' : '#4B5563';

  useEffect(() => {
    if (!containerRef.current) return;

    // Filter valid elements to prevent Cytoscape orphaned edge errors
    const validNodeIds = new Set(
      elements.filter((el) => !el.data.source && !el.data.target).map((el) => el.data.id)
    );
    const safeElements = elements.filter((el) => {
      if (el.data.source && el.data.target) {
        return validNodeIds.has(el.data.source) && validNodeIds.has(el.data.target);
      }
      return true;
    });

    try {
      const cy = cytoscape({
        container: containerRef.current,
        elements: safeElements as any,
        style: [
          {
            selector: 'node',
            style: {
              'label': 'data(label)',
              'color': nodeTextColor,
              'font-size': '10px',
              'font-family': 'JetBrains Mono, monospace',
              'text-valign': 'bottom',
              'text-margin-y': 5,
              'background-color': isLight ? '#D1D5DB' : '#374151',
              'border-width': 2,
              'border-color': isLight ? '#9CA3AF' : '#1F2937',
              'width': 34,
              'height': 34,
              'text-background-opacity': 0.85,
              'text-background-color': nodeTextBg,
              'text-background-padding': '3px',
              'text-background-shape': 'roundrectangle',
            },
          },
          // Node Type Styling
          {
            selector: 'node[type = "process"]',
            style: {
              'background-color': '#06B6D4',
              'border-color': '#22D3EE',
              'shape': 'roundrectangle',
            },
          },
          {
            selector: 'node[type = "account"]',
            style: {
              'background-color': '#8B5CF6',
              'border-color': '#A78BFA',
              'shape': 'ellipse',
            },
          },
          {
            selector: 'node[type = "network_endpoint"]',
            style: {
              'background-color': '#F59E0B',
              'border-color': '#FBBF24',
              'shape': 'diamond',
              'width': 38,
              'height': 38,
            },
          },
          {
            selector: 'node[type = "evidence"]',
            style: {
              'background-color': '#10B981',
              'border-color': '#34D399',
              'shape': 'hexagon',
            },
          },
          {
            selector: 'node[type = "mitre_assessment"]',
            style: {
              'background-color': '#EF4444',
              'border-color': '#F87171',
              'shape': 'round-tag',
            },
          },
          {
            selector: 'node[type = "limitation"]',
            style: {
              'background-color': isLight ? '#9CA3AF' : '#4B5563',
              'border-color': isLight ? '#6B7280' : '#6B7280',
              'shape': 'rectangle',
              'width': 26,
              'height': 26,
            },
          },
          // Selected Node Highlight
          {
            selector: 'node:selected',
            style: {
              'border-color': isLight ? '#0284C7' : '#FFFFFF',
              'border-width': 4,
            },
          },
          // Edge Styling
          {
            selector: 'edge',
            style: {
              'label': 'data(label)',
              'font-size': '8px',
              'color': isLight ? '#6B7280' : '#9CA3AF',
              'font-family': 'JetBrains Mono, monospace',
              'text-rotation': 'autorotate',
              'text-margin-y': -6,
              'width': 2,
              'line-color': edgeColor,
              'target-arrow-color': edgeArrowColor,
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              'arrow-scale': 1.1,
            },
          },
          {
            selector: 'edge[type = "process_spawn"]',
            style: {
              'line-color': '#06B6D4',
              'target-arrow-color': '#06B6D4',
              'width': 2.5,
            },
          },
          {
            selector: 'edge[type = "supports_assessment"]',
            style: {
              'line-color': '#EF4444',
              'target-arrow-color': '#EF4444',
              'line-style': 'dashed',
            },
          },
        ],
        layout: {
          name: 'cose',
          animate: true,
          animationDuration: 400,
          nodeRepulsion: () => 400000,
          nodeOverlap: 20,
          idealEdgeLength: () => 90,
          edgeElasticity: () => 100,
          padding: 30,
        },
      });

      cy.on('tap', 'node', (evt) => {
        const node = evt.target;
        onSelectNode(node.data());
      });

      cyRef.current = cy;
    } catch (err) {
      console.error('Cytoscape initialization error:', err);
    }

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [elements, theme]);

  // Sync selected node
  useEffect(() => {
    if (!cyRef.current) return;
    cyRef.current.nodes().unselect();
    if (selectedNodeId) {
      cyRef.current.$id(selectedNodeId).select();
    }
  }, [selectedNodeId]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() / 1.25);
  const handleFit = () => cyRef.current?.fit(undefined, 25);

  return (
    <div className={`relative w-full h-full rounded-2xl overflow-hidden border ${isLight ? 'bg-[#FAFAFA]' : 'bg-[#080C14]'}`} style={{ borderColor: 'var(--border-glass)' }}>
      <div ref={containerRef} className="w-full h-full" />

      {/* MacOS Style Floating Controls Pill */}
      <div className="absolute bottom-4 right-4 flex items-center gap-1 glass-card border rounded-full px-2 py-1 shadow-xl">
        <button
          onClick={handleZoomIn}
          className="p-1.5 text-gray-400 hover:text-cyan-400 rounded-full transition"
          title="Phóng to"
        >
          <ZoomInIcon className="w-3.5 h-3.5" />
        </button>
        <div className="w-[1px] h-3 bg-gray-700/50" />
        <button
          onClick={handleZoomOut}
          className="p-1.5 text-gray-400 hover:text-cyan-400 rounded-full transition"
          title="Thu nhỏ"
        >
          <ZoomOutIcon className="w-3.5 h-3.5" />
        </button>
        <div className="w-[1px] h-3 bg-gray-700/50" />
        <button
          onClick={handleFit}
          className="p-1.5 text-gray-400 hover:text-cyan-400 rounded-full transition"
          title="Toàn cảnh"
        >
          <MaximizeIcon className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Legend Badge */}
      <div className="absolute top-4 left-4 glass-card border rounded-xl px-3 py-1.5 text-[10px] font-mono flex items-center gap-3.5 shadow-lg pointer-events-none">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-sm bg-[#06B6D4]" />
          <span>Process</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-[#8B5CF6]" />
          <span>Account</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rotate-45 bg-[#F59E0B]" />
          <span>Endpoint</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-sm bg-[#10B981]" />
          <span>Evidence</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-sm bg-[#EF4444]" />
          <span>MITRE</span>
        </div>
      </div>
    </div>
  );
};
